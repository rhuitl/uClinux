#ifndef MODINFO_DOT_H
#define MODINFO_DOT_H

#define MAX_VARNAME 100
#define MAX_VARDESC 256

#define MODINFO_TYPE_INT     (1<<0)
#define MODINFO_TYPE_FLOAT   (1<<1)
#define MODINFO_TYPE_STR     (1<<2)

typedef struct modinfo_query_st {
  int nVars;
  struct {
    int type;
    char varname[ MAX_VARNAME + 1];
    char description[ MAX_VARDESC + 1];
  } *vars;
} ModInfo;

typedef ModInfo *(*ModInfo_QueryFunc)();

extern void modinfo_destroy( ModInfo *minfo );
extern ModInfo *modinfo_create( int nVars );
extern void modinfo_varname_set( ModInfo *minfo,int vnum,const char *newname );
extern void modinfo_desc_set( ModInfo *minfo, int vnum, const char *new_desc );
extern ModInfo *modinfo_query_so( const char *soname );
extern void modinfo_dump( const ModInfo *minfo );

#endif
