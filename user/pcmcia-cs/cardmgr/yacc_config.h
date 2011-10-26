#define DEVICE 257
#define CARD 258
#define ANONYMOUS 259
#define TUPLE 260
#define MANFID 261
#define VERSION 262
#define FUNCTION 263
#define PCI 264
#define BIND 265
#define CIS 266
#define TO 267
#define NEEDS_MTD 268
#define MODULE 269
#define OPTS 270
#define CLASS 271
#define REGION 272
#define JEDEC 273
#define DTYPE 274
#define DEFAULT 275
#define MTD 276
#define INCLUDE 277
#define EXCLUDE 278
#define RESERVE 279
#define IRQ_NO 280
#define PORT 281
#define MEMORY 282
#define STRING 283
#define NUMBER 284
typedef union {
    char *str;
    u_long num;
    struct device_info_t *device;
    struct card_info_t *card;
    struct mtd_ident_t *mtd;
    struct adjust_list_t *adjust;
} YYSTYPE;
extern YYSTYPE yylval;
