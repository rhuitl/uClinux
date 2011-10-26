typedef union {
    int num;
    char *str;
    struct sockaddr_atmpvc pvc;
} YYSTYPE;
#define	TOK_LEVEL	257
#define	TOK_DEBUG	258
#define	TOK_INFO	259
#define	TOK_WARN	260
#define	TOK_ERROR	261
#define	TOK_FATAL	262
#define	TOK_SIG	263
#define	TOK_UNI30	264
#define	TOK_UNI31	265
#define	TOK_UNI40	266
#define	TOK_Q2963_1	267
#define	TOK_SAAL	268
#define	TOK_VC	269
#define	TOK_IO	270
#define	TOK_MODE	271
#define	TOK_USER	272
#define	TOK_NET	273
#define	TOK_SWITCH	274
#define	TOK_VPCI	275
#define	TOK_ITF	276
#define	TOK_PCR	277
#define	TOK_TRACE	278
#define	TOK_POLICY	279
#define	TOK_ALLOW	280
#define	TOK_REJECT	281
#define	TOK_ENTITY	282
#define	TOK_DEFAULT	283
#define	TOK_NUMBER	284
#define	TOK_MAX_RATE	285
#define	TOK_DUMP_DIR	286
#define	TOK_LOGFILE	287
#define	TOK_QOS	288
#define	TOK_FROM	289
#define	TOK_TO	290
#define	TOK_ROUTE	291
#define	TOK_PVC	292


extern YYSTYPE yylval;
