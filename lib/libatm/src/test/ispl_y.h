typedef union {
    char *str;
    int num;
    enum atmsvc_msg_type type;
    VAR *var;
} YYSTYPE;
#define	TOK_SEND	257
#define	TOK_WAIT	258
#define	TOK_RECEIVE	259
#define	TOK_HELP	260
#define	TOK_SET	261
#define	TOK_SHOW	262
#define	TOK_ECHO	263
#define	TOK_VCC	264
#define	TOK_LISTEN	265
#define	TOK_LISTEN_VCC	266
#define	TOK_REPLY	267
#define	TOK_PVC	268
#define	TOK_LOCAL	269
#define	TOK_QOS	270
#define	TOK_SVC	271
#define	TOK_BIND	272
#define	TOK_CONNECT	273
#define	TOK_ACCEPT	274
#define	TOK_REJECT	275
#define	TOK_OKAY	276
#define	TOK_ERROR	277
#define	TOK_INDICATE	278
#define	TOK_CLOSE	279
#define	TOK_ITF_NOTIFY	280
#define	TOK_MODIFY	281
#define	TOK_SAP	282
#define	TOK_IDENTIFY	283
#define	TOK_TERMINATE	284
#define	TOK_EOL	285
#define	TOK_VALUE	286
#define	TOK_VARIABLE	287


extern YYSTYPE yylval;
