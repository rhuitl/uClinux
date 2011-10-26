#ifndef CAMCONFIG_DOT_H
#define CAMCONFIG_DOT_H

#define MAX_SECTION_NAME   40

#define SEC_MAIN      "main"
#define SEC_VIDEO     "video"
#define SEC_FILTERS   "filters"
#define SEC_SOCKET    "socket"
#define SEC_CAMCMD    "camcmd"

#define CAMCONFIG_DEF_LISTEN_PORT 9191

typedef struct camconfig_section_st CamConfigSection;
typedef struct camconfig_st CamConfig;

extern CamConfig *camconfig_new();
extern void camconfig_dest( CamConfig *ccfg );
extern CamConfig *camconfig_read( FILE *fp );
extern int camconfig_set_str( CamConfig *ccfg, char *secname, char *key, 
			      char *val );
extern int camconfig_set_int( CamConfig *ccfg, char *secname, char *key, 
			      int val );
extern const char *camconfig_query_str( CamConfig *ccfg, char *secname, 
					char *key );
extern int camconfig_query_int( CamConfig *ccfg, char *secname, char *key, 
				int *err);
extern float camconfig_query_def_float( CamConfig *ccfg, char *secname, 
					char *key, float def );
extern int camconfig_query_def_int( CamConfig *ccfg, char *secname, 
				    char *key,int def);

#endif
