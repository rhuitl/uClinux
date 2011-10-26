typedef union {
	long itype;
	double rtype;
	char *str;
	TREE *tree;
	SYMTAB *sym;
	EXPR *expr;
	BOUND *bound;
	LHELM *lhelm;
	MINDEX *mindex;
	FORELM *forelm;
	FORSTMT *forstmt;
	OWNTYPE otype;
	ENUM type_tag typ;
} YYSTYPE;
#define	TCOMMENT	258
#define	TTEN	259
#define	TBEGIN	260
#define	TEND	261
#define	TGOTO	262
#define	TFOR	263
#define	TDO	264
#define	TWHILE	265
#define	TSTEP	266
#define	TUNTIL	267
#define	TIF	268
#define	TTHEN	269
#define	TELSE	270
#define	TSWITCH	271
#define	TPROC	272
#define	TVALUE	273
#define	TCODE	274
#define	TTRUE	275
#define	TFALSE	276
#define	TINTEGER	277
#define	TREAL	278
#define	TBOOL	279
#define	TLABEL	280
#define	TOWN	281
#define	TARRAY	282
#define	TSTRING	283
#define	TPOW	284
#define	TDIV	285
#define	TASSIGN	286
#define	TLESS	287
#define	TNOTGREATER	288
#define	TEQUAL	289
#define	TNOTLESS	290
#define	TGREATER	291
#define	TNOTEQUAL	292
#define	TAND	293
#define	TOR	294
#define	TNOT	295
#define	TIMPL	296
#define	TEQUIV	297
#define	INUM	298
#define	RNUM	299
#define	NAME	300
#define	STRING	301
#define	UNARY	302


extern YYSTYPE yylval;
