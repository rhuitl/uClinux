#ifndef ___CONFIG_H
#define ___CONFIG_H

#ident "$Id: config.h,v 4.4 2005/02/09 09:44:19 gert Exp $ Copyright (c) 1993 Gert Doering"

/* type definitions, prototypes, defines needed for configuration stuff
 */

#ifdef PTR_IS_LONG
 typedef long p_int;	/* a "long" is the same size as an "char *" */
#else
 typedef int p_int;	/* an "int" is the same size as an "char *" */
#endif

typedef struct conf_data {
		   char * key;
		   union { p_int i; void * p; } d;
		   enum { CT_INT, CT_STRING, CT_CHAT, CT_BOOL,
			  CT_FLOWL, CT_ACTION, CT_KEYWORD } type;
		   enum { C_EMPTY, C_PRESET, C_OVERRIDE, C_CONF,
			  C_IGNORE } flags;
		 } conf_data;

int get_config _PROTO(( char * conf_file, conf_data * cd,
		        char * section_key, char * key_value ));

void display_cd _PROTO(( conf_data * cd ));

char * fgetline _PROTO(( FILE * fp ));
void   norm_line _PROTO(( char ** line, char ** key ));
void * conf_get_chat _PROTO(( char * line ));

#ifndef ERROR
#define ERROR -1
#define NOERROR 0
#endif


/* macros for effecient initializing of "conf_data" values */

#define conf_set_string( cp, s ) { (cp)->d.p = (s); (cp)->flags = C_OVERRIDE; }
#define conf_set_bool( cp, b )   { (cp)->d.i = (b); (cp)->flags = C_OVERRIDE; }
#define conf_set_int( cp, n )    { (cp)->d.i = (n); (cp)->flags = C_OVERRIDE; }

/* macros for implementation-indepentent access */
#define c_isset( cp )	( c.cp.flags != C_EMPTY )
#define c_string( cp )	((char *) c.cp.d.p)
#define c_bool( cp )	((int) c.cp.d.i)
#define c_int( cp )	((int) c.cp.d.i)
#define c_chat( cp )	((char **) c.cp.d.p)

/* concatenate two paths (if second path doesn't start with "/") */
/* two variants: ANSI w/ macro, K&R w/ C subroutine in config.c  */
#ifdef __STDC__
#define makepath( file, base ) ((file)[0] == '/'? (file) : (base"/"file))
#else
#define makepath( file, base ) _makepath( file, base )
#endif
extern char * _makepath _PROTO(( char * file, char * base ));

#endif			/* ___CONFIG_H */
