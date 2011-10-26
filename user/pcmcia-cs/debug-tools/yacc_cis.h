#define STRING 257
#define NUMBER 258
#define FLOAT 259
#define VOLTAGE 260
#define CURRENT 261
#define SIZE 262
#define VERS_1 263
#define MANFID 264
#define FUNCID 265
#define CONFIG 266
#define CFTABLE 267
#define MFC 268
#define CHECKSUM 269
#define POST 270
#define ROM 271
#define BASE 272
#define LAST_INDEX 273
#define CJEDEC 274
#define AJEDEC 275
#define DEV_INFO 276
#define ATTR_DEV_INFO 277
#define NO_INFO 278
#define TIME 279
#define TIMING 280
#define WAIT 281
#define READY 282
#define RESERVED 283
#define VNOM 284
#define VMIN 285
#define VMAX 286
#define ISTATIC 287
#define IAVG 288
#define IPEAK 289
#define IDOWN 290
#define VCC 291
#define VPP1 292
#define VPP2 293
#define IO 294
#define MEM 295
#define DEFAULT 296
#define BVD 297
#define WP 298
#define RDYBSY 299
#define MWAIT 300
#define AUDIO 301
#define READONLY 302
#define PWRDOWN 303
#define BIT8 304
#define BIT16 305
#define LINES 306
#define RANGE 307
#define IRQ_NO 308
#define MASK 309
#define LEVEL 310
#define PULSE 311
#define SHARED 312
typedef union {
    char *str;
    u_long num;
    float flt;
    cistpl_power_t pwr;
    cisparse_t *parse;
    tuple_info_t *tuple;
} YYSTYPE;
extern YYSTYPE yylval;
