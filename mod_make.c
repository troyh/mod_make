#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_config.h>
#include <apache2/http_log.h>
#include <regex.h>
#include <apr_strings.h>

typedef struct {
	int onoff;
	const char* sourceRoot;
	const char* makefileName;
	const char* makeProgram;
	const char* makeOptions;
	const char* includeFileTypes;
	const char* excludeFileTypes;
	// const char* excludeRegex;
	const char* errorURI;
	const char* errorCSS;
	int debug;
} dir_cfg;

static const char* cfg_set_filetype(cmd_parms* cmd, void* cfg, const char* val);
static void* create_dir_conf(apr_pool_t* pool, char* x);
static void make_hooks(apr_pool_t *pool);
	
static const command_rec cmds[]={
	AP_INIT_FLAG("Make",				  ap_set_flag_slot,   (void*)APR_OFFSETOF(dir_cfg,onoff),	        OR_ALL,"Enable mod_make"),
	AP_INIT_TAKE1("MakeSourceRoot",		  ap_set_string_slot, (void*)APR_OFFSETOF(dir_cfg,sourceRoot),	    OR_ALL,"Source root"),
	AP_INIT_TAKE1("MakeFilename",		  ap_set_string_slot, (void*)APR_OFFSETOF(dir_cfg,makefileName),    OR_ALL,"Make filename (i.e., Makefile)"),
	AP_INIT_TAKE1("MakeProgram",		  ap_set_string_slot, (void*)APR_OFFSETOF(dir_cfg,makeProgram),	    OR_ALL,"Make binary"),
	AP_INIT_TAKE1("MakeOptions",		  ap_set_string_slot, (void*)APR_OFFSETOF(dir_cfg,makeOptions),	    OR_ALL,"Make options"),
	AP_INIT_ITERATE("MakeIncludeFileTypes", cfg_set_filetype, (void*)APR_OFFSETOF(dir_cfg,includeFileTypes),OR_ALL,"Include file types"),
	AP_INIT_ITERATE("MakeExcludeFileTypes", cfg_set_filetype, (void*)APR_OFFSETOF(dir_cfg,excludeFileTypes),OR_ALL,"Exclude file types"),
	// AP_INIT_TAKE1("MakeExcludeRegex",	  ap_set_string_slot, (void*)APR_OFFSETOF(dir_cfg,excludeRegex),	OR_ALL,"Exclude regex"),
	AP_INIT_TAKE1("MakeErrorURI",		  ap_set_string_slot, (void*)APR_OFFSETOF(dir_cfg,errorURI),		OR_ALL,"Error URI"),
	AP_INIT_TAKE1("MakeErrorCSS",		  ap_set_string_slot, (void*)APR_OFFSETOF(dir_cfg,errorCSS),		OR_ALL,"Error CSS"),
	AP_INIT_FLAG("MakeDebug",			  ap_set_flag_slot,   (void*)APR_OFFSETOF(dir_cfg,debug),	        OR_ALL,"Enable mod_make debug mode"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA make_module = {
        STANDARD20_MODULE_STUFF,
        create_dir_conf,
        NULL,
        NULL,
        NULL,
        cmds,
        make_hooks
} ;

/**
 *	Handles the error page, when necessary.
 */
static int make_handler(request_rec *r) {
	if (!r || !r->uri)
		return HTTP_INTERNAL_SERVER_ERROR;
		
	dir_cfg* cfg=ap_get_module_config(r->per_dir_config,&make_module);
	if (strcmp(r->uri,cfg->errorURI))
		return DECLINED;
		
    ap_set_content_type(r, "text/html;charset=ascii");

	const char* make_output=apr_table_get(r->prev->notes,"make_output");
	// ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make handler:make_output:%s",make_output);
	ap_rprintf(r,
		"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n"
		"<html><head><title>mod_make</title>"
		"<link rel=\"stylesheet\" type=\"text/css\" href=\"%s\" />"
		"</head>"
		"<body><h1>Make Error:</h1><pre>%s</pre></body></html>",
		cfg->errorCSS,
		make_output);
		
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
		
	dir_cfg* cfg=ap_get_module_config(r->per_dir_config,&make_module);
	if (!cfg->onoff) // Is module turned on?
		return DECLINED;
		
	const char* docroot=ap_document_root(r);

	if (cfg->debug) {
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:onoff:%d",cfg->onoff);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:sourceRoot:%s",cfg->sourceRoot);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:makefileName:%s",cfg->makefileName);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:makeProgram:%s",cfg->makeProgram);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:makeOptions:%s",cfg->makeOptions);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:includeFileTypes:%s",cfg->includeFileTypes);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:excludeFileTypes:%s",cfg->excludeFileTypes);
		// ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:excludeRegex:%s",cfg->excludeRegex);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:errorURI:%s",cfg->errorURI);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cfg:errorCSS:%s",cfg->errorCSS);
	}
	
	// Determine if this is a request I care about, i.e., the following is true:
	// The file type is in MakeIncludeFileTypes (if specified) and is not in MakeExcludeFileTypes (if specified)
	if (cfg->includeFileTypes || cfg->excludeFileTypes) {
		// Get file extension
		char* fname=basename(r->canonical_filename);
		char* ext=strchr(fname,'.');
		if (ext) {
			if (cfg->includeFileTypes && !strcasestr(cfg->includeFileTypes,ext)) {
				return DECLINED;
			}
			if (cfg->excludeFileTypes && strcasestr(cfg->excludeFileTypes,ext)) {
				return DECLINED;
			}
		}
	}
		
	// Locate Makefile: The Makefile should be in SourceRoot/REL_PATH/Makefile
	char relpath[256];
	char makefile[256];
	char make_target[64];

	// Determine the relative path part of r->canonical_filename, i.e., the part with the DocumentRoot removed
	strncpy(relpath,r->canonical_filename+strlen(docroot)-1,sizeof(relpath)-1);
	// Truncate it before the basename
	char* p=strrchr(relpath,'/');
	if (p)
		*++p='\0';
	else {
		relpath[0]='/';
		relpath[1]='\0';
	}

	// Determine the make target, i.e., the basename of r->canonical_filename
	strncpy(make_target,r->canonical_filename+strlen(docroot)-1+strlen(relpath),sizeof(make_target)-1);
	make_target[sizeof(make_target)-1]='\0';
	
	strncpy(makefile,cfg->sourceRoot,sizeof(makefile)-1);
	strncat(makefile,relpath,sizeof(makefile)-strlen(makefile)-1);
	strncat(makefile,cfg->makefileName,sizeof(makefile)-strlen(makefile)-1);
	makefile[sizeof(makefile)-1]='\0';
	
	if (cfg->debug) {
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: relpath:%s",relpath);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: makefile:%s",makefile);
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: make_target:%s",make_target);
	}
	
	// If Makefile not found, ignore it (we only care if there •is* a Makefile)
	struct stat ss;
	if (stat(makefile,&ss)) {
		return DECLINED;
	}

	// Build make command
	char* cmd=apr_psprintf(r->pool,"WWWDOCROOT=%s WWWRELPATH=%s %s -f %s -C %s %s %s 2>&1",
		docroot,
		relpath,
		cfg->makeProgram,
		cfg->makefileName,
		(const char*)dirname(makefile),
		cfg->makeOptions,
		make_target);

	if (cfg->debug)
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: cmd:%s",cmd);
	
	// Run Makefile to make target
	FILE* makep=popen(cmd,"r");
	if (!makep) { // If launching make fails, output errors from make and return HTTP error
		if (cfg->debug)
			ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: failed to popen:%s",cmd);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// Compile regex
	regex_t regex;
	char* regexstr=apr_psprintf(r->pool,
		"^make:[[:space:]]+\\*\\*\\*[[:space:]]+No[[:space:]]+rule[[:space:]]+to[[:space:]]+make[[:space:]]+target[[:space:]]+`%s'\\.[[:space:]]+Stop\\.",
		make_target
		);
	if (regcomp(&regex,regexstr,REG_EXTENDED)) {
		if (cfg->debug)
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
			if (cfg->debug)
				ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: make output:%s",newp);
			make_output_size-=strlen(newp);
			p+=strlen(newp);
			
			if (regexec(&regex,newp,0,0,0)==0) {
				if (cfg->debug)
					ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: regex match:%s",newp);
				bSilentFail=TRUE;
			}

		}
	}
	while (!feof(makep) && make_output_size>1);
	
	if (!make_output_size) {
		if (cfg->debug)
			ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: make output exceeded max length");
		// TODO: add appropriate message to make_output
	}

	int ret=pclose(makep);
	
	if (cfg->debug)
		ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: make exit code:%d",WEXITSTATUS(ret));
	
	if (WEXITSTATUS(ret)) {// make did not complete successfully, output make's output and tell Apache to stop.
		if (bSilentFail) {
			if (cfg->debug)
				ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,"mod_make: silently failing.");
			return DECLINED;
		}
		
		// Store make_output in request_rec so that the handler can display it 
		apr_table_set(r->notes,"make_output",make_output);
		// Redirect to our own content handler
		ap_internal_redirect(cfg->errorURI,r);
		return OK;
	}
	
    return DECLINED;
}

static void make_hooks(apr_pool_t *pool) {
    ap_hook_fixups(make_fixup, NULL, NULL, APR_HOOK_LAST);
    ap_hook_handler(make_handler, NULL, NULL, APR_HOOK_FIRST);
}

/**
 * Configuration functions
 */
static void* create_dir_conf(apr_pool_t* pool, char* x) {
	dir_cfg* cfg=(dir_cfg*)apr_pcalloc(pool,sizeof(dir_cfg));
	// Set defaults
	cfg->sourceRoot="./";
	cfg->makefileName="Makefile";
	cfg->makeProgram="make";
	cfg->makeOptions="";
	cfg->includeFileTypes=0;
	cfg->excludeFileTypes=0;
	// cfg->excludeRegex="";
	cfg->errorURI="/mod_make_error";
	cfg->errorCSS="";
	cfg->debug=0;
	
	return cfg;
}

static const char* cfg_set_filetype(cmd_parms* cmd, void* cfg, const char* val) {
	int offset=(int)(long)cmd->info;
	char* str=*(char**)((char*)cfg+offset);
	if (!str)
		str=apr_pstrcat(cmd->pool,val,NULL);
	else
		str=apr_pstrcat(cmd->pool,str," ",val,NULL);
	*(char**)((char*)cfg+offset)=str;
	return NULL;
}
