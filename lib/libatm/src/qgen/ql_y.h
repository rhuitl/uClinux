typedef union {
    const char *str;
    int num;
    FIELD *field;
    VALUE *value;
    VALUE_LIST *list;
    TAG *tag;
    NAME_LIST *nlist;
} YYSTYPE;
#define	TOK_BREAK	257
#define	TOK_CASE	258
#define	TOK_DEF	259
#define	TOK_DEFAULT	260
#define	TOK_LENGTH	261
#define	TOK_MULTI	262
#define	TOK_RECOVER	263
#define	TOK_ABORT	264
#define	TOK_ID	265
#define	TOK_INCLUDE	266
#define	TOK_STRING	267


extern YYSTYPE yylval;
