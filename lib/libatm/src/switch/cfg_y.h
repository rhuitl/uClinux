typedef union {
    int num;
    char *str;
    struct sockaddr_atmpvc pvc;
} YYSTYPE;
#define	TOK_COMMAND	257
#define	TOK_VPCI	258
#define	TOK_ITF	259
#define	TOK_DEFAULT	260
#define	TOK_ROUTE	261
#define	TOK_STR	262
#define	TOK_SOCKET	263
#define	TOK_OPTION	264
#define	TOK_CONTROL	265
#define	TOK_NUM	266
#define	TOK_PVC	267


extern YYSTYPE yylval;
