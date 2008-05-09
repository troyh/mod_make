#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <apache2/http_log.h>

// Configurable options
const char* DOCUMENT_ROOT="/var/www/";
const char* SOURCE_ROOT="/home/troy/app/";
const char* MAKEFILE_NAME="/Makefile";
const char* MAKE_OPTIONS="";

/**
TODO:
- Make above params configurable
- Make sure MAKEFILE_NAME has a leading slash
- Make sure SOURCE_ROOT has a trailing slash
- Make sure DOCUMENT_ROOT has a trailing slash
- Allow a config option to specify file types to include or exclude (so it doesn't try to make .gif files, for example)
*/

const size_t MAX_PATH=255;

static int printitem(void *rec, const char *key, const char *value)
{
    /* rec is a user data pointer.  We'll pass the request_rec in it. */
    request_rec *r = rec;
    ap_rprintf(r, "<tr><th scope=\"row\">%s</th><td>%s</td></tr>\n",
           ap_escape_html(r->pool, key),
           ap_escape_html(r->pool, value));
    /* Zero would stop iterating; any other return value continues */
    return 1;
}

static void printtable(request_rec *r, apr_table_t *t,
                 const char *caption, const char *keyhead,
                 const char *valhead)
{
    /* Print a table header */
    ap_rprintf(r, "<table><caption>%s</caption><thead>"
           "<tr><th scope=\"col\">%s</th><th scope=\"col\">%s"
           "</th></tr></thead><tbody>", caption, keyhead, valhead);

    /* Print the data: apr_table_do iterates over entries with
     * our callback
     */
    apr_table_do(printitem, r, t, NULL);

    /* Finish the table */
    ap_rputs("</tbody></table>\n", r);
}

static int make_handler(request_rec *r) {
	if (!r)
		return HTTP_INTERNAL_SERVER_ERROR;
		
	// Locate Makefile: The Makefile should be in SOURCE_ROOT/REL_PATH/Makefile
	char makefile[MAX_PATH];
	strncpy(makefile,SOURCE_ROOT,sizeof(makefile)-1);
	// Copy the relative part of r->canonical_filename, i.e., the part with the DocumentRoot removed
	strncat(makefile,r->canonical_filename+strlen(DOCUMENT_ROOT),sizeof(makefile)-strlen(makefile)-1);
	// Truncate it before the basename
	char* p=strrchr(makefile,'/');
	if (!p)
		return DECLINED; // No decipherable make target, give up
		
	*p='\0'; // Truncate it
	
	// Determine the make target, i.e., the basename of r->canonical_filename
	char make_target[32];
	strncpy(make_target,++p,sizeof(make_target)-1);
	make_target[sizeof(make_target)-1]='\0';
		
	strncat(makefile,MAKEFILE_NAME,sizeof(makefile)-strlen(makefile)-1);
	makefile[sizeof(makefile)-1]='\0';
	
	// If Makefile not found, ignore it (we only care if there •is* a Makefile)
	struct stat ss;
	if (stat(makefile,&ss)) {
		return DECLINED;
	}

	// Build make command
	char cmd[255];
	strncpy(cmd,"make -C ",sizeof(cmd)-1);
	strncat(cmd,(const char*)dirname(makefile),sizeof(cmd)-strlen(cmd)-1);
	strncat(cmd,MAKE_OPTIONS,sizeof(cmd)-strlen(cmd)-1);
	strncat(cmd," ",sizeof(cmd)-strlen(cmd)-1);
	strncat(cmd,make_target,sizeof(cmd)-strlen(cmd)-1);
	strncat(cmd," 2>&1",sizeof(cmd)-strlen(cmd)-1);
	cmd[sizeof(cmd)-1]='\0';
	
	// Run Makefile to make target
	FILE* makep=popen(cmd,"r");
	if (!makep) { // If launching make fails, output errors from make and return HTTP error
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: failed to popen:%s",cmd);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char make_output[1024]="";
	// Read output of make
	do {
		fgets(make_output+strlen(make_output),sizeof(make_output)-strlen(make_output),makep);
	} while(!feof(makep));
	make_output[sizeof(make_output)-1]='\0';
	
	int ret=pclose(makep);
	if (WEXITSTATUS(ret)) {// make did not complete successfully, output make's output and tell Apache to stop.
	    ap_set_content_type(r, "text/html;charset=ascii");
	    ap_rputs("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n",r);
	    ap_rputs("<html><head><title>mod_make</title></head>", r);
	    ap_rputs("<body><h1>Make:</h1>", r);
	
		ap_rprintf(r,"<div id=\"mod_make\"><div id=\"cmd\">%s</div>",cmd,makefile);
		// ap_rprintf(r,"<div>Return code:%d</div>",WEXITSTATUS(ret));
		ap_rprintf(r,"<pre id=\"output\">%s</pre></div>",make_output);

		// printtable(r, r->headers_in, "Request Headers", "Header", "Value");
		// printtable(r, r->headers_out, "Response Headers", "Header", "Value");
		// printtable(r, r->subprocess_env, "Environment", "Variable", "Value");

		// ap_rputs("<div>the_request:",r);	ap_rputs(r->the_request,r);ap_rputs("</div>",r);
		// ap_rputs("<div>protocol:",r);		ap_rputs(r->protocol,r);ap_rputs("</div>",r);
		// // ap_rputs("<div>status_line:",r);	ap_rputs(r->status_line,r);ap_rputs("</div>",r);
		// ap_rputs("<div>method:",r);		ap_rputs(r->method,r);ap_rputs("</div>",r);
		// ap_rputs("<div>unparsed_uri:",r);	ap_rputs(r->unparsed_uri,r);ap_rputs("</div>",r);
		// ap_rputs("<div>uri:",r);			ap_rputs(r->uri,r);ap_rputs("</div>",r);
		// ap_rputs("<div>filename:",r);		ap_rputs(r->filename,r);ap_rputs("</div>",r);
		// ap_rputs("<div>canonical_filename:",r);ap_rputs(r->canonical_filename,r);ap_rputs("</div>",r);
		// ap_rputs("<div>path_info:",r);	ap_rputs(r->path_info,r);ap_rputs("</div>",r);
		// // ap_rputs("<div>args:",r);			ap_rputs(r->args,r);ap_rputs("</div>",r);
	    ap_rputs("</body></html>", r);

		return OK;
	}
	
	// If all ok, return DECLINED so that Apache continues to let the request continue

    return DECLINED;
}

static void make_hooks(apr_pool_t *pool) {
    ap_hook_fixups(make_handler, NULL, NULL, APR_HOOK_LAST);
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
