#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <apache2/http_log.h>
#include <regex.h>
#include <apr_strings.h>

// Configurable options
const char* DOCUMENT_ROOT="/var/www";
const char* SOURCE_ROOT="/home/troy/app"; // MakeSourceRoot
const char* MAKEFILE_NAME="Makefile"; // MakeFilename
const char* MAKE_PROG="make"; // MakeProgram
const char* MAKE_OPTIONS=""; // MakeOptions
const char* INCLUDE_FILE_TYPES=""; // MakeIncludeFileTypes
const char* EXCLUDE_FILE_TYPES=""; // MakeExcludeFileTypes
const char* EXCLUDE_REGEX=""; // MakeExcludeRegex
const char* MAKEERROR_URI="/mod_make_error"; // MakeErrorURI

/**
TODO:
- Make above params configurable
- Allow a config option to specify file types to include or exclude (so it doesn't try to make .gif files, for example)
- Handle non-existent make targets gracefully. We have to run make, but if it says something like the following, silently fail:

	make: Entering directory `/home/troy/app'
	make: *** No rule to make target `blah.html'.  Stop.
	make: Leaving directory `/home/troy/app'

*/

const size_t MAX_PATH=255; // TODO: use OS' equivalent

/**
 *	Handles the error page, when necessary.
 */
static int make_handler(request_rec *r) {
	if (!r || !r->uri)
		return HTTP_INTERNAL_SERVER_ERROR;
		
	if (strcmp(r->uri,MAKEERROR_URI))
		return DECLINED;
		
    ap_set_content_type(r, "text/html;charset=ascii");
    ap_rputs("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n",r);
    ap_rputs("<html><head><title>mod_make</title></head>", r);
    ap_rputs("<body><h1>Make Error:</h1>", r);

	const char* make_output=apr_table_get(r->prev->notes,"make_output");
	// ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make handler:make_output:%s",make_output);
	ap_rprintf(r,"<pre>%s</pre>",make_output);

    ap_rputs("</body></html>", r);
		
	return OK;
}

/**
 *	Performs the make, if necessary
 */
static int make_fixup(request_rec *r) {
	if (!r)
		return HTTP_INTERNAL_SERVER_ERROR;
	if (r->prev)
		return DECLINED; // We're running in a sub-request, ignore.
		
	// TODO: Determine if this is a request I care about, i.e., the following are true:
	// 1. The file type is in MakeIncludeFileTypes (if specified) and is not in MakeExcludeFileTypes (if specified)
	// 2. The URI does not match the MakeExcludeRegex expression
		
	// Locate Makefile: The Makefile should be in SOURCE_ROOT/REL_PATH/Makefile
	char relpath[MAX_PATH];
	char makefile[MAX_PATH];
	char make_target[64];

	// Determine the relative path part of r->canonical_filename, i.e., the part with the DocumentRoot removed
	strncpy(relpath,r->canonical_filename+strlen(DOCUMENT_ROOT),sizeof(relpath)-1);
	// Truncate it before the basename
	char* p=strrchr(relpath,'/');
	if (p)
		*++p='\0';
	else {
		relpath[0]='/';
		relpath[1]='\0';
	}

	// Determine the make target, i.e., the basename of r->canonical_filename
	strncpy(make_target,r->canonical_filename+strlen(DOCUMENT_ROOT)+strlen(relpath),sizeof(make_target)-1);
	make_target[sizeof(make_target)-1]='\0';
	
	strncpy(makefile,SOURCE_ROOT,sizeof(makefile)-1);
	strncat(makefile,relpath,sizeof(makefile)-strlen(makefile)-1);
	strncat(makefile,MAKEFILE_NAME,sizeof(makefile)-strlen(makefile)-1);
	makefile[sizeof(makefile)-1]='\0';
	
	ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: relpath:%s",relpath);
	ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: makefile:%s",makefile);
	ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: make_target:%s",make_target);
	
	// If Makefile not found, ignore it (we only care if there •is* a Makefile)
	struct stat ss;
	if (stat(makefile,&ss)) {
		return DECLINED;
	}

	// Build make command
	char* cmd=apr_psprintf(r->pool,"WWWDOCROOT=%s WWWRELPATH=%s %s -f %s -C %s %s %s 2>&1",
		DOCUMENT_ROOT,
		relpath,
		MAKE_PROG,
		MAKEFILE_NAME,
		(const char*)dirname(makefile),
		MAKE_OPTIONS,
		make_target);
		
	ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cmd:%s",cmd);
	
	// Run Makefile to make target
	FILE* makep=popen(cmd,"r");
	if (!makep) { // If launching make fails, output errors from make and return HTTP error
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: failed to popen:%s",cmd);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// Compile regex
	regex_t regex;
	// if (regcomp(&regex,"make: \\*\\*\\* No rule to make target `.+'\\. Stop\\.",0)) {
	if (regcomp(&regex,"No rule to make target",0)) {
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: regcomp failed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	int bSilentFail=FALSE;

	// Read output of make
	size_t make_output_size=10240; // TODO: allow the buffer to grow beyond 10K
	char* make_output=apr_palloc(r->pool,make_output_size);
	make_output[0]='\0';
	make_output_size--;
	p=make_output; // reuse p
	do {
		const char* newp=fgets(p,make_output_size,makep);
		if (newp) {
			make_output_size-=strlen(newp);
			p+=strlen(newp);
			
			if (regexec(&regex,newp,0,0,0)==0) {
				ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: regex match:%s",newp);
				bSilentFail=TRUE;
			}

		}
	}
	while (!feof(makep));

	int ret=pclose(makep);
	
	ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: make exit code:%d",WEXITSTATUS(ret));
	
	if (WEXITSTATUS(ret)) {// make did not complete successfully, output make's output and tell Apache to stop.
		// TODO: Look for regex 'make: \*\*\* No rule to make target `[TARGET]'' and if found, silently fail
		if (bSilentFail) {
			ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: silently failing.");
			return DECLINED;
		}
		
		// Store make_output in request_rec so that the handler can display it 
		apr_table_set(r->notes,"make_output",make_output);
		// Redirect to our own content handler
		ap_internal_redirect(MAKEERROR_URI,r);
		return OK;
	}
	
    return DECLINED;
}

static void make_hooks(apr_pool_t *pool) {
    ap_hook_fixups(make_fixup, NULL, NULL, APR_HOOK_LAST);
    ap_hook_handler(make_handler, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA make_module = {
        STANDARD20_MODULE_STUFF,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        make_hooks
} ;
