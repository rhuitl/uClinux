/* A Bison parser, made from sql_yacc.yy, by GNU bison 1.75.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON	1

/* Pure parsers.  */
#define YYPURE	1

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     END_OF_INPUT = 258,
     CLOSE_SYM = 259,
     HANDLER_SYM = 260,
     LAST_SYM = 261,
     NEXT_SYM = 262,
     PREV_SYM = 263,
     EQ = 264,
     EQUAL_SYM = 265,
     GE = 266,
     GT_SYM = 267,
     LE = 268,
     LT = 269,
     NE = 270,
     IS = 271,
     SHIFT_LEFT = 272,
     SHIFT_RIGHT = 273,
     SET_VAR = 274,
     ABORT_SYM = 275,
     ADD = 276,
     AFTER_SYM = 277,
     ALTER = 278,
     ANALYZE_SYM = 279,
     AVG_SYM = 280,
     BEGIN_SYM = 281,
     BINLOG_SYM = 282,
     CHANGE = 283,
     CLIENT_SYM = 284,
     COMMENT_SYM = 285,
     COMMIT_SYM = 286,
     COUNT_SYM = 287,
     CREATE = 288,
     CROSS = 289,
     CUBE_SYM = 290,
     DELETE_SYM = 291,
     DO_SYM = 292,
     DROP = 293,
     EVENTS_SYM = 294,
     EXECUTE_SYM = 295,
     FLUSH_SYM = 296,
     INSERT = 297,
     IO_THREAD = 298,
     KILL_SYM = 299,
     LOAD = 300,
     LOCKS_SYM = 301,
     LOCK_SYM = 302,
     MASTER_SYM = 303,
     MAX_SYM = 304,
     MIN_SYM = 305,
     NONE_SYM = 306,
     OPTIMIZE = 307,
     PURGE = 308,
     REPAIR = 309,
     REPLICATION = 310,
     RESET_SYM = 311,
     ROLLBACK_SYM = 312,
     ROLLUP_SYM = 313,
     SAVEPOINT_SYM = 314,
     SELECT_SYM = 315,
     SHOW = 316,
     SLAVE = 317,
     SQL_THREAD = 318,
     START_SYM = 319,
     STD_SYM = 320,
     STOP_SYM = 321,
     SUM_SYM = 322,
     SUPER_SYM = 323,
     TRUNCATE_SYM = 324,
     UNLOCK_SYM = 325,
     UPDATE_SYM = 326,
     ACTION = 327,
     AGGREGATE_SYM = 328,
     ALL = 329,
     AND = 330,
     AS = 331,
     ASC = 332,
     AUTO_INC = 333,
     AVG_ROW_LENGTH = 334,
     BACKUP_SYM = 335,
     BERKELEY_DB_SYM = 336,
     BINARY = 337,
     BIT_SYM = 338,
     BOOL_SYM = 339,
     BOOLEAN_SYM = 340,
     BOTH = 341,
     BY = 342,
     CACHE_SYM = 343,
     CASCADE = 344,
     CAST_SYM = 345,
     CHARSET = 346,
     CHECKSUM_SYM = 347,
     CHECK_SYM = 348,
     COMMITTED_SYM = 349,
     COLUMNS = 350,
     COLUMN_SYM = 351,
     CONCURRENT = 352,
     CONSTRAINT = 353,
     CONVERT_SYM = 354,
     DATABASES = 355,
     DATA_SYM = 356,
     DEFAULT = 357,
     DELAYED_SYM = 358,
     DELAY_KEY_WRITE_SYM = 359,
     DESC = 360,
     DESCRIBE = 361,
     DES_KEY_FILE = 362,
     DISABLE_SYM = 363,
     DISTINCT = 364,
     DYNAMIC_SYM = 365,
     ENABLE_SYM = 366,
     ENCLOSED = 367,
     ESCAPED = 368,
     DIRECTORY_SYM = 369,
     ESCAPE_SYM = 370,
     EXISTS = 371,
     EXTENDED_SYM = 372,
     FILE_SYM = 373,
     FIRST_SYM = 374,
     FIXED_SYM = 375,
     FLOAT_NUM = 376,
     FORCE_SYM = 377,
     FOREIGN = 378,
     FROM = 379,
     FULL = 380,
     FULLTEXT_SYM = 381,
     GLOBAL_SYM = 382,
     GRANT = 383,
     GRANTS = 384,
     GREATEST_SYM = 385,
     GROUP = 386,
     HAVING = 387,
     HEAP_SYM = 388,
     HEX_NUM = 389,
     HIGH_PRIORITY = 390,
     HOSTS_SYM = 391,
     IDENT = 392,
     IGNORE_SYM = 393,
     INDEX = 394,
     INDEXES = 395,
     INFILE = 396,
     INNER_SYM = 397,
     INNOBASE_SYM = 398,
     INTO = 399,
     IN_SYM = 400,
     ISOLATION = 401,
     ISAM_SYM = 402,
     JOIN_SYM = 403,
     KEYS = 404,
     KEY_SYM = 405,
     LEADING = 406,
     LEAST_SYM = 407,
     LEVEL_SYM = 408,
     LEX_HOSTNAME = 409,
     LIKE = 410,
     LINES = 411,
     LOCAL_SYM = 412,
     LOG_SYM = 413,
     LOGS_SYM = 414,
     LONG_NUM = 415,
     LONG_SYM = 416,
     LOW_PRIORITY = 417,
     MASTER_HOST_SYM = 418,
     MASTER_USER_SYM = 419,
     MASTER_LOG_FILE_SYM = 420,
     MASTER_LOG_POS_SYM = 421,
     MASTER_PASSWORD_SYM = 422,
     MASTER_PORT_SYM = 423,
     MASTER_CONNECT_RETRY_SYM = 424,
     MASTER_SERVER_ID_SYM = 425,
     RELAY_LOG_FILE_SYM = 426,
     RELAY_LOG_POS_SYM = 427,
     MATCH = 428,
     MAX_ROWS = 429,
     MAX_CONNECTIONS_PER_HOUR = 430,
     MAX_QUERIES_PER_HOUR = 431,
     MAX_UPDATES_PER_HOUR = 432,
     MEDIUM_SYM = 433,
     MERGE_SYM = 434,
     MEMORY_SYM = 435,
     MIN_ROWS = 436,
     MYISAM_SYM = 437,
     NATIONAL_SYM = 438,
     NATURAL = 439,
     NEW_SYM = 440,
     NCHAR_SYM = 441,
     NOT = 442,
     NO_SYM = 443,
     NULL_SYM = 444,
     NUM = 445,
     OFFSET_SYM = 446,
     ON = 447,
     OPEN_SYM = 448,
     OPTION = 449,
     OPTIONALLY = 450,
     OR = 451,
     OR_OR_CONCAT = 452,
     ORDER_SYM = 453,
     OUTER = 454,
     OUTFILE = 455,
     DUMPFILE = 456,
     PACK_KEYS_SYM = 457,
     PARTIAL = 458,
     PRIMARY_SYM = 459,
     PRIVILEGES = 460,
     PROCESS = 461,
     PROCESSLIST_SYM = 462,
     QUERY_SYM = 463,
     RAID_0_SYM = 464,
     RAID_STRIPED_SYM = 465,
     RAID_TYPE = 466,
     RAID_CHUNKS = 467,
     RAID_CHUNKSIZE = 468,
     READ_SYM = 469,
     REAL_NUM = 470,
     REFERENCES = 471,
     REGEXP = 472,
     RELOAD = 473,
     RENAME = 474,
     REPEATABLE_SYM = 475,
     REQUIRE_SYM = 476,
     RESOURCES = 477,
     RESTORE_SYM = 478,
     RESTRICT = 479,
     REVOKE = 480,
     ROWS_SYM = 481,
     ROW_FORMAT_SYM = 482,
     ROW_SYM = 483,
     SET = 484,
     SERIALIZABLE_SYM = 485,
     SESSION_SYM = 486,
     SHUTDOWN = 487,
     SSL_SYM = 488,
     STARTING = 489,
     STATUS_SYM = 490,
     STRAIGHT_JOIN = 491,
     SUBJECT_SYM = 492,
     TABLES = 493,
     TABLE_SYM = 494,
     TEMPORARY = 495,
     TERMINATED = 496,
     TEXT_STRING = 497,
     TO_SYM = 498,
     TRAILING = 499,
     TRANSACTION_SYM = 500,
     TYPE_SYM = 501,
     FUNC_ARG0 = 502,
     FUNC_ARG1 = 503,
     FUNC_ARG2 = 504,
     FUNC_ARG3 = 505,
     UDF_RETURNS_SYM = 506,
     UDF_SONAME_SYM = 507,
     UDF_SYM = 508,
     UNCOMMITTED_SYM = 509,
     UNION_SYM = 510,
     UNIQUE_SYM = 511,
     USAGE = 512,
     USE_FRM = 513,
     USE_SYM = 514,
     USING = 515,
     VALUES = 516,
     VARIABLES = 517,
     WHERE = 518,
     WITH = 519,
     WRITE_SYM = 520,
     X509_SYM = 521,
     XOR = 522,
     COMPRESSED_SYM = 523,
     BIGINT = 524,
     BLOB_SYM = 525,
     CHAR_SYM = 526,
     CHANGED = 527,
     COALESCE = 528,
     DATETIME = 529,
     DATE_SYM = 530,
     DECIMAL_SYM = 531,
     DOUBLE_SYM = 532,
     ENUM = 533,
     FAST_SYM = 534,
     FLOAT_SYM = 535,
     INT_SYM = 536,
     LIMIT = 537,
     LONGBLOB = 538,
     LONGTEXT = 539,
     MEDIUMBLOB = 540,
     MEDIUMINT = 541,
     MEDIUMTEXT = 542,
     NUMERIC_SYM = 543,
     PRECISION = 544,
     QUICK = 545,
     REAL = 546,
     SIGNED_SYM = 547,
     SMALLINT = 548,
     STRING_SYM = 549,
     TEXT_SYM = 550,
     TIMESTAMP = 551,
     TIME_SYM = 552,
     TINYBLOB = 553,
     TINYINT = 554,
     TINYTEXT = 555,
     ULONGLONG_NUM = 556,
     UNSIGNED = 557,
     VARBINARY = 558,
     VARCHAR = 559,
     VARYING = 560,
     ZEROFILL = 561,
     AGAINST = 562,
     ATAN = 563,
     BETWEEN_SYM = 564,
     BIT_AND = 565,
     BIT_OR = 566,
     CASE_SYM = 567,
     CONCAT = 568,
     CONCAT_WS = 569,
     CURDATE = 570,
     CURTIME = 571,
     DATABASE = 572,
     DATE_ADD_INTERVAL = 573,
     DATE_SUB_INTERVAL = 574,
     DAY_HOUR_SYM = 575,
     DAY_MINUTE_SYM = 576,
     DAY_SECOND_SYM = 577,
     DAY_SYM = 578,
     DECODE_SYM = 579,
     DES_ENCRYPT_SYM = 580,
     DES_DECRYPT_SYM = 581,
     ELSE = 582,
     ELT_FUNC = 583,
     ENCODE_SYM = 584,
     ENCRYPT = 585,
     EXPORT_SET = 586,
     EXTRACT_SYM = 587,
     FIELD_FUNC = 588,
     FORMAT_SYM = 589,
     FOR_SYM = 590,
     FROM_UNIXTIME = 591,
     GROUP_UNIQUE_USERS = 592,
     HOUR_MINUTE_SYM = 593,
     HOUR_SECOND_SYM = 594,
     HOUR_SYM = 595,
     IDENTIFIED_SYM = 596,
     IF = 597,
     INSERT_METHOD = 598,
     INTERVAL_SYM = 599,
     LAST_INSERT_ID = 600,
     LEFT = 601,
     LOCATE = 602,
     MAKE_SET_SYM = 603,
     MASTER_POS_WAIT = 604,
     MINUTE_SECOND_SYM = 605,
     MINUTE_SYM = 606,
     MODE_SYM = 607,
     MODIFY_SYM = 608,
     MONTH_SYM = 609,
     NOW_SYM = 610,
     PASSWORD = 611,
     POSITION_SYM = 612,
     PROCEDURE = 613,
     RAND = 614,
     REPLACE = 615,
     RIGHT = 616,
     ROUND = 617,
     SECOND_SYM = 618,
     SHARE_SYM = 619,
     SUBSTRING = 620,
     SUBSTRING_INDEX = 621,
     TRIM = 622,
     UDA_CHAR_SUM = 623,
     UDA_FLOAT_SUM = 624,
     UDA_INT_SUM = 625,
     UDF_CHAR_FUNC = 626,
     UDF_FLOAT_FUNC = 627,
     UDF_INT_FUNC = 628,
     UNIQUE_USERS = 629,
     UNIX_TIMESTAMP = 630,
     USER = 631,
     WEEK_SYM = 632,
     WHEN_SYM = 633,
     WORK_SYM = 634,
     YEAR_MONTH_SYM = 635,
     YEAR_SYM = 636,
     YEARWEEK = 637,
     BENCHMARK_SYM = 638,
     END = 639,
     THEN_SYM = 640,
     SQL_BIG_RESULT = 641,
     SQL_CACHE_SYM = 642,
     SQL_CALC_FOUND_ROWS = 643,
     SQL_NO_CACHE_SYM = 644,
     SQL_SMALL_RESULT = 645,
     SQL_BUFFER_RESULT = 646,
     ISSUER_SYM = 647,
     CIPHER_SYM = 648,
     NEG = 649
   };
#endif
#define END_OF_INPUT 258
#define CLOSE_SYM 259
#define HANDLER_SYM 260
#define LAST_SYM 261
#define NEXT_SYM 262
#define PREV_SYM 263
#define EQ 264
#define EQUAL_SYM 265
#define GE 266
#define GT_SYM 267
#define LE 268
#define LT 269
#define NE 270
#define IS 271
#define SHIFT_LEFT 272
#define SHIFT_RIGHT 273
#define SET_VAR 274
#define ABORT_SYM 275
#define ADD 276
#define AFTER_SYM 277
#define ALTER 278
#define ANALYZE_SYM 279
#define AVG_SYM 280
#define BEGIN_SYM 281
#define BINLOG_SYM 282
#define CHANGE 283
#define CLIENT_SYM 284
#define COMMENT_SYM 285
#define COMMIT_SYM 286
#define COUNT_SYM 287
#define CREATE 288
#define CROSS 289
#define CUBE_SYM 290
#define DELETE_SYM 291
#define DO_SYM 292
#define DROP 293
#define EVENTS_SYM 294
#define EXECUTE_SYM 295
#define FLUSH_SYM 296
#define INSERT 297
#define IO_THREAD 298
#define KILL_SYM 299
#define LOAD 300
#define LOCKS_SYM 301
#define LOCK_SYM 302
#define MASTER_SYM 303
#define MAX_SYM 304
#define MIN_SYM 305
#define NONE_SYM 306
#define OPTIMIZE 307
#define PURGE 308
#define REPAIR 309
#define REPLICATION 310
#define RESET_SYM 311
#define ROLLBACK_SYM 312
#define ROLLUP_SYM 313
#define SAVEPOINT_SYM 314
#define SELECT_SYM 315
#define SHOW 316
#define SLAVE 317
#define SQL_THREAD 318
#define START_SYM 319
#define STD_SYM 320
#define STOP_SYM 321
#define SUM_SYM 322
#define SUPER_SYM 323
#define TRUNCATE_SYM 324
#define UNLOCK_SYM 325
#define UPDATE_SYM 326
#define ACTION 327
#define AGGREGATE_SYM 328
#define ALL 329
#define AND 330
#define AS 331
#define ASC 332
#define AUTO_INC 333
#define AVG_ROW_LENGTH 334
#define BACKUP_SYM 335
#define BERKELEY_DB_SYM 336
#define BINARY 337
#define BIT_SYM 338
#define BOOL_SYM 339
#define BOOLEAN_SYM 340
#define BOTH 341
#define BY 342
#define CACHE_SYM 343
#define CASCADE 344
#define CAST_SYM 345
#define CHARSET 346
#define CHECKSUM_SYM 347
#define CHECK_SYM 348
#define COMMITTED_SYM 349
#define COLUMNS 350
#define COLUMN_SYM 351
#define CONCURRENT 352
#define CONSTRAINT 353
#define CONVERT_SYM 354
#define DATABASES 355
#define DATA_SYM 356
#define DEFAULT 357
#define DELAYED_SYM 358
#define DELAY_KEY_WRITE_SYM 359
#define DESC 360
#define DESCRIBE 361
#define DES_KEY_FILE 362
#define DISABLE_SYM 363
#define DISTINCT 364
#define DYNAMIC_SYM 365
#define ENABLE_SYM 366
#define ENCLOSED 367
#define ESCAPED 368
#define DIRECTORY_SYM 369
#define ESCAPE_SYM 370
#define EXISTS 371
#define EXTENDED_SYM 372
#define FILE_SYM 373
#define FIRST_SYM 374
#define FIXED_SYM 375
#define FLOAT_NUM 376
#define FORCE_SYM 377
#define FOREIGN 378
#define FROM 379
#define FULL 380
#define FULLTEXT_SYM 381
#define GLOBAL_SYM 382
#define GRANT 383
#define GRANTS 384
#define GREATEST_SYM 385
#define GROUP 386
#define HAVING 387
#define HEAP_SYM 388
#define HEX_NUM 389
#define HIGH_PRIORITY 390
#define HOSTS_SYM 391
#define IDENT 392
#define IGNORE_SYM 393
#define INDEX 394
#define INDEXES 395
#define INFILE 396
#define INNER_SYM 397
#define INNOBASE_SYM 398
#define INTO 399
#define IN_SYM 400
#define ISOLATION 401
#define ISAM_SYM 402
#define JOIN_SYM 403
#define KEYS 404
#define KEY_SYM 405
#define LEADING 406
#define LEAST_SYM 407
#define LEVEL_SYM 408
#define LEX_HOSTNAME 409
#define LIKE 410
#define LINES 411
#define LOCAL_SYM 412
#define LOG_SYM 413
#define LOGS_SYM 414
#define LONG_NUM 415
#define LONG_SYM 416
#define LOW_PRIORITY 417
#define MASTER_HOST_SYM 418
#define MASTER_USER_SYM 419
#define MASTER_LOG_FILE_SYM 420
#define MASTER_LOG_POS_SYM 421
#define MASTER_PASSWORD_SYM 422
#define MASTER_PORT_SYM 423
#define MASTER_CONNECT_RETRY_SYM 424
#define MASTER_SERVER_ID_SYM 425
#define RELAY_LOG_FILE_SYM 426
#define RELAY_LOG_POS_SYM 427
#define MATCH 428
#define MAX_ROWS 429
#define MAX_CONNECTIONS_PER_HOUR 430
#define MAX_QUERIES_PER_HOUR 431
#define MAX_UPDATES_PER_HOUR 432
#define MEDIUM_SYM 433
#define MERGE_SYM 434
#define MEMORY_SYM 435
#define MIN_ROWS 436
#define MYISAM_SYM 437
#define NATIONAL_SYM 438
#define NATURAL 439
#define NEW_SYM 440
#define NCHAR_SYM 441
#define NOT 442
#define NO_SYM 443
#define NULL_SYM 444
#define NUM 445
#define OFFSET_SYM 446
#define ON 447
#define OPEN_SYM 448
#define OPTION 449
#define OPTIONALLY 450
#define OR 451
#define OR_OR_CONCAT 452
#define ORDER_SYM 453
#define OUTER 454
#define OUTFILE 455
#define DUMPFILE 456
#define PACK_KEYS_SYM 457
#define PARTIAL 458
#define PRIMARY_SYM 459
#define PRIVILEGES 460
#define PROCESS 461
#define PROCESSLIST_SYM 462
#define QUERY_SYM 463
#define RAID_0_SYM 464
#define RAID_STRIPED_SYM 465
#define RAID_TYPE 466
#define RAID_CHUNKS 467
#define RAID_CHUNKSIZE 468
#define READ_SYM 469
#define REAL_NUM 470
#define REFERENCES 471
#define REGEXP 472
#define RELOAD 473
#define RENAME 474
#define REPEATABLE_SYM 475
#define REQUIRE_SYM 476
#define RESOURCES 477
#define RESTORE_SYM 478
#define RESTRICT 479
#define REVOKE 480
#define ROWS_SYM 481
#define ROW_FORMAT_SYM 482
#define ROW_SYM 483
#define SET 484
#define SERIALIZABLE_SYM 485
#define SESSION_SYM 486
#define SHUTDOWN 487
#define SSL_SYM 488
#define STARTING 489
#define STATUS_SYM 490
#define STRAIGHT_JOIN 491
#define SUBJECT_SYM 492
#define TABLES 493
#define TABLE_SYM 494
#define TEMPORARY 495
#define TERMINATED 496
#define TEXT_STRING 497
#define TO_SYM 498
#define TRAILING 499
#define TRANSACTION_SYM 500
#define TYPE_SYM 501
#define FUNC_ARG0 502
#define FUNC_ARG1 503
#define FUNC_ARG2 504
#define FUNC_ARG3 505
#define UDF_RETURNS_SYM 506
#define UDF_SONAME_SYM 507
#define UDF_SYM 508
#define UNCOMMITTED_SYM 509
#define UNION_SYM 510
#define UNIQUE_SYM 511
#define USAGE 512
#define USE_FRM 513
#define USE_SYM 514
#define USING 515
#define VALUES 516
#define VARIABLES 517
#define WHERE 518
#define WITH 519
#define WRITE_SYM 520
#define X509_SYM 521
#define XOR 522
#define COMPRESSED_SYM 523
#define BIGINT 524
#define BLOB_SYM 525
#define CHAR_SYM 526
#define CHANGED 527
#define COALESCE 528
#define DATETIME 529
#define DATE_SYM 530
#define DECIMAL_SYM 531
#define DOUBLE_SYM 532
#define ENUM 533
#define FAST_SYM 534
#define FLOAT_SYM 535
#define INT_SYM 536
#define LIMIT 537
#define LONGBLOB 538
#define LONGTEXT 539
#define MEDIUMBLOB 540
#define MEDIUMINT 541
#define MEDIUMTEXT 542
#define NUMERIC_SYM 543
#define PRECISION 544
#define QUICK 545
#define REAL 546
#define SIGNED_SYM 547
#define SMALLINT 548
#define STRING_SYM 549
#define TEXT_SYM 550
#define TIMESTAMP 551
#define TIME_SYM 552
#define TINYBLOB 553
#define TINYINT 554
#define TINYTEXT 555
#define ULONGLONG_NUM 556
#define UNSIGNED 557
#define VARBINARY 558
#define VARCHAR 559
#define VARYING 560
#define ZEROFILL 561
#define AGAINST 562
#define ATAN 563
#define BETWEEN_SYM 564
#define BIT_AND 565
#define BIT_OR 566
#define CASE_SYM 567
#define CONCAT 568
#define CONCAT_WS 569
#define CURDATE 570
#define CURTIME 571
#define DATABASE 572
#define DATE_ADD_INTERVAL 573
#define DATE_SUB_INTERVAL 574
#define DAY_HOUR_SYM 575
#define DAY_MINUTE_SYM 576
#define DAY_SECOND_SYM 577
#define DAY_SYM 578
#define DECODE_SYM 579
#define DES_ENCRYPT_SYM 580
#define DES_DECRYPT_SYM 581
#define ELSE 582
#define ELT_FUNC 583
#define ENCODE_SYM 584
#define ENCRYPT 585
#define EXPORT_SET 586
#define EXTRACT_SYM 587
#define FIELD_FUNC 588
#define FORMAT_SYM 589
#define FOR_SYM 590
#define FROM_UNIXTIME 591
#define GROUP_UNIQUE_USERS 592
#define HOUR_MINUTE_SYM 593
#define HOUR_SECOND_SYM 594
#define HOUR_SYM 595
#define IDENTIFIED_SYM 596
#define IF 597
#define INSERT_METHOD 598
#define INTERVAL_SYM 599
#define LAST_INSERT_ID 600
#define LEFT 601
#define LOCATE 602
#define MAKE_SET_SYM 603
#define MASTER_POS_WAIT 604
#define MINUTE_SECOND_SYM 605
#define MINUTE_SYM 606
#define MODE_SYM 607
#define MODIFY_SYM 608
#define MONTH_SYM 609
#define NOW_SYM 610
#define PASSWORD 611
#define POSITION_SYM 612
#define PROCEDURE 613
#define RAND 614
#define REPLACE 615
#define RIGHT 616
#define ROUND 617
#define SECOND_SYM 618
#define SHARE_SYM 619
#define SUBSTRING 620
#define SUBSTRING_INDEX 621
#define TRIM 622
#define UDA_CHAR_SUM 623
#define UDA_FLOAT_SUM 624
#define UDA_INT_SUM 625
#define UDF_CHAR_FUNC 626
#define UDF_FLOAT_FUNC 627
#define UDF_INT_FUNC 628
#define UNIQUE_USERS 629
#define UNIX_TIMESTAMP 630
#define USER 631
#define WEEK_SYM 632
#define WHEN_SYM 633
#define WORK_SYM 634
#define YEAR_MONTH_SYM 635
#define YEAR_SYM 636
#define YEARWEEK 637
#define BENCHMARK_SYM 638
#define END 639
#define THEN_SYM 640
#define SQL_BIG_RESULT 641
#define SQL_CACHE_SYM 642
#define SQL_CALC_FOUND_ROWS 643
#define SQL_NO_CACHE_SYM 644
#define SQL_SMALL_RESULT 645
#define SQL_BUFFER_RESULT 646
#define ISSUER_SYM 647
#define CIPHER_SYM 648
#define NEG 649




/* Copy the first part of user declarations.  */
#line 19 "sql_yacc.yy"

#define MYSQL_YACC
#define YYINITDEPTH 100
#define YYMAXDEPTH 3200				/* Because of 64K stack */
#define Lex current_lex
#define Select Lex->select
#include "mysql_priv.h"
#include "slave.h"
#include "sql_acl.h"
#include "lex_symbol.h"
#include <myisam.h>
#include <myisammrg.h>

extern void yyerror(const char*);
int yylex(void *yylval);

#define yyoverflow(A,B,C,D,E,F) if (my_yyoverflow((B),(D),(int*) (F))) { yyerror((char*) (A)); return 2; }

inline Item *or_or_concat(Item* A, Item* B)
{
  return (current_thd->sql_mode & MODE_PIPES_AS_CONCAT ?
          (Item*) new Item_func_concat(A,B) : (Item*) new Item_cond_or(A,B));
}



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#ifndef YYSTYPE
#line 44 "sql_yacc.yy"
typedef union {
  int  num;
  ulong ulong_num;
  ulonglong ulonglong_number;
  LEX_STRING lex_str;
  LEX_STRING *lex_str_ptr;
  LEX_SYMBOL symbol;
  Table_ident *table;
  char *simple_string;
  Item *item;
  List<Item> *item_list;
  List<String> *string_list;
  String *string;
  key_part_spec *key_part;
  TABLE_LIST *table_list;
  udf_func *udf;
  LEX_USER *lex_user;
  sys_var *variable;
  Key::Keytype key_type;
  enum db_type db_type;
  enum row_type row_type;
  enum ha_rkey_function ha_rkey_mode;
  enum enum_tx_isolation tx_isolation;
  enum Item_cast cast_type;
  enum Item_udftype udf_type;
  thr_lock_type lock_type;
  interval_type interval;
} yystype;
/* Line 193 of /usr/share/bison/yacc.c.  */
#line 916 "y.tab.c"
# define YYSTYPE yystype
# define YYSTYPE_IS_TRIVIAL 1
#endif

#ifndef YYLTYPE
typedef struct yyltype
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
} yyltype;
# define YYLTYPE yyltype
# define YYLTYPE_IS_TRIVIAL 1
#endif

/* Copy the second part of user declarations.  */
#line 73 "sql_yacc.yy"

bool my_yyoverflow(short **a, YYSTYPE **b,int *yystacksize);


/* Line 213 of /usr/share/bison/yacc.c.  */
#line 940 "y.tab.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC malloc
#  define YYSTACK_FREE free
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (YYLTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAX (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAX)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];	\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAX;	\
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  410
#define YYLAST   25694

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  412
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  367
/* YYNRULES -- Number of rules. */
#define YYNRULES  1285
/* YYNRULES -- Number of states. */
#define YYNSTATES  2408

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   649

#define YYTRANSLATE(X) \
  ((unsigned)(X) <= YYMAXUTOK ? yytranslate[X] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned short yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   407,     2,     2,     2,   400,   395,     2,
     404,   405,   398,   397,   406,   396,   411,   399,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,   410,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,   403,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   408,   394,   409,   401,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     215,   216,   217,   218,   219,   220,   221,   222,   223,   224,
     225,   226,   227,   228,   229,   230,   231,   232,   233,   234,
     235,   236,   237,   238,   239,   240,   241,   242,   243,   244,
     245,   246,   247,   248,   249,   250,   251,   252,   253,   254,
     255,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   402
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned short yyprhs[] =
{
       0,     0,     3,     5,     8,    10,    12,    14,    16,    18,
      20,    22,    24,    26,    28,    30,    32,    34,    36,    38,
      40,    42,    44,    46,    48,    50,    52,    54,    56,    58,
      60,    62,    64,    66,    68,    70,    72,    74,    76,    78,
      80,    82,    84,    85,    91,    93,    97,   101,   105,   109,
     113,   117,   121,   125,   129,   133,   134,   142,   143,   154,
     159,   160,   170,   173,   176,   181,   182,   187,   188,   189,
     195,   196,   204,   205,   211,   212,   214,   215,   217,   219,
     222,   224,   225,   229,   230,   232,   234,   237,   241,   245,
     249,   253,   257,   261,   265,   269,   273,   277,   281,   285,
     289,   293,   297,   303,   307,   312,   316,   321,   326,   328,
     330,   332,   334,   336,   338,   340,   342,   344,   346,   348,
     350,   352,   354,   356,   358,   360,   361,   364,   365,   367,
     369,   371,   373,   375,   379,   381,   383,   386,   389,   395,
     404,   407,   408,   411,   412,   415,   416,   421,   425,   429,
     433,   436,   438,   444,   447,   452,   458,   463,   467,   469,
     471,   473,   478,   480,   482,   484,   486,   488,   491,   494,
     496,   498,   500,   502,   506,   510,   511,   517,   518,   524,
     526,   528,   531,   534,   536,   539,   542,   544,   546,   548,
     550,   552,   554,   556,   559,   560,   564,   566,   572,   573,
     575,   578,   580,   582,   584,   586,   587,   591,   592,   594,
     595,   597,   600,   602,   604,   607,   610,   612,   615,   617,
     620,   623,   624,   626,   631,   635,   642,   643,   645,   648,
     650,   654,   658,   661,   664,   666,   668,   671,   674,   677,
     681,   683,   685,   688,   691,   695,   697,   699,   701,   703,
     705,   706,   708,   710,   715,   718,   720,   725,   726,   728,
     730,   734,   735,   742,   743,   745,   749,   752,   756,   759,
     764,   765,   772,   773,   774,   783,   788,   792,   797,   801,
     804,   807,   814,   820,   824,   826,   828,   829,   831,   832,
     834,   835,   837,   839,   840,   843,   845,   846,   848,   850,
     852,   856,   860,   864,   868,   869,   873,   875,   879,   880,
     882,   884,   885,   892,   893,   900,   901,   907,   908,   910,
     912,   915,   917,   919,   921,   922,   928,   929,   935,   936,
     938,   940,   943,   945,   947,   949,   951,   953,   954,   960,
     961,   966,   968,   972,   976,   978,   979,   984,   985,   992,
     993,   999,  1001,  1003,  1006,  1009,  1018,  1019,  1021,  1024,
    1026,  1028,  1030,  1032,  1034,  1036,  1038,  1040,  1042,  1044,
    1046,  1047,  1050,  1055,  1059,  1061,  1063,  1068,  1069,  1070,
    1072,  1074,  1075,  1078,  1081,  1083,  1085,  1086,  1089,  1091,
    1093,  1099,  1106,  1112,  1119,  1123,  1127,  1131,  1135,  1140,
    1146,  1150,  1155,  1159,  1164,  1168,  1172,  1176,  1180,  1184,
    1188,  1192,  1196,  1200,  1204,  1208,  1212,  1216,  1220,  1224,
    1228,  1232,  1238,  1244,  1250,  1257,  1261,  1265,  1269,  1273,
    1278,  1284,  1288,  1293,  1297,  1302,  1306,  1310,  1314,  1318,
    1322,  1326,  1330,  1334,  1338,  1342,  1346,  1350,  1354,  1358,
    1362,  1366,  1370,  1376,  1382,  1384,  1390,  1397,  1403,  1410,
    1414,  1418,  1422,  1427,  1433,  1437,  1442,  1446,  1451,  1455,
    1459,  1463,  1467,  1471,  1475,  1479,  1483,  1487,  1491,  1495,
    1499,  1503,  1507,  1511,  1515,  1519,  1525,  1531,  1533,  1535,
    1537,  1542,  1545,  1550,  1552,  1555,  1558,  1561,  1564,  1568,
    1573,  1580,  1590,  1593,  1600,  1607,  1614,  1618,  1623,  1630,
    1639,  1644,  1651,  1656,  1661,  1666,  1673,  1676,  1679,  1684,
    1693,  1702,  1706,  1713,  1720,  1725,  1732,  1739,  1746,  1751,
    1758,  1763,  1770,  1779,  1790,  1803,  1810,  1815,  1822,  1829,
    1834,  1843,  1854,  1860,  1867,  1871,  1876,  1883,  1890,  1899,
    1906,  1913,  1918,  1925,  1932,  1941,  1946,  1951,  1954,  1959,
    1964,  1971,  1976,  1980,  1989,  1996,  2001,  2008,  2013,  2022,
    2029,  2038,  2045,  2054,  2059,  2067,  2075,  2083,  2090,  2097,
    2102,  2107,  2112,  2117,  2122,  2127,  2138,  2142,  2147,  2151,
    2156,  2163,  2168,  2173,  2180,  2187,  2194,  2195,  2197,  2202,
    2207,  2212,  2218,  2223,  2224,  2225,  2233,  2244,  2249,  2254,
    2259,  2264,  2265,  2269,  2271,  2273,  2275,  2278,  2280,  2283,
    2285,  2287,  2289,  2290,  2293,  2295,  2299,  2301,  2305,  2306,
    2309,  2311,  2315,  2316,  2318,  2319,  2322,  2323,  2326,  2330,
    2336,  2337,  2339,  2343,  2345,  2349,  2353,  2357,  2363,  2364,
    2373,  2381,  2382,  2393,  2400,  2408,  2409,  2420,  2427,  2432,
    2434,  2437,  2440,  2441,  2446,  2457,  2458,  2460,  2461,  2464,
    2467,  2470,  2471,  2477,  2481,  2483,  2485,  2487,  2491,  2493,
    2495,  2497,  2499,  2501,  2503,  2505,  2507,  2509,  2511,  2513,
    2515,  2517,  2518,  2520,  2522,  2523,  2526,  2527,  2529,  2530,
    2533,  2534,  2535,  2539,  2542,  2543,  2544,  2549,  2554,  2557,
    2558,  2561,  2564,  2565,  2567,  2568,  2573,  2578,  2581,  2582,
    2584,  2586,  2587,  2588,  2592,  2594,  2598,  2602,  2603,  2606,
    2608,  2610,  2612,  2614,  2616,  2618,  2620,  2622,  2624,  2626,
    2627,  2628,  2635,  2636,  2638,  2642,  2644,  2647,  2648,  2655,
    2659,  2660,  2664,  2671,  2672,  2679,  2684,  2688,  2690,  2694,
    2696,  2697,  2700,  2701,  2703,  2704,  2705,  2713,  2714,  2715,
    2722,  2723,  2725,  2727,  2729,  2731,  2733,  2736,  2738,  2740,
    2742,  2746,  2751,  2752,  2756,  2757,  2761,  2764,  2768,  2770,
    2773,  2774,  2778,  2779,  2785,  2789,  2791,  2795,  2797,  2801,
    2803,  2805,  2806,  2808,  2809,  2814,  2815,  2817,  2821,  2823,
    2825,  2827,  2828,  2839,  2845,  2849,  2850,  2852,  2853,  2858,
    2859,  2866,  2867,  2873,  2874,  2881,  2883,  2887,  2890,  2895,
    2896,  2899,  2900,  2903,  2905,  2907,  2911,  2912,  2914,  2915,
    2919,  2922,  2926,  2931,  2936,  2943,  2960,  2963,  2966,  2967,
    2974,  2979,  2982,  2985,  2988,  2992,  2994,  2998,  3002,  3005,
    3008,  3009,  3012,  3013,  3016,  3017,  3019,  3021,  3023,  3024,
    3027,  3028,  3031,  3032,  3037,  3040,  3042,  3044,  3045,  3047,
    3049,  3050,  3054,  3058,  3060,  3061,  3065,  3070,  3073,  3075,
    3077,  3079,  3081,  3083,  3085,  3087,  3089,  3090,  3092,  3093,
    3097,  3101,  3103,  3105,  3107,  3110,  3111,  3118,  3121,  3124,
    3125,  3141,  3147,  3152,  3153,  3155,  3156,  3158,  3160,  3161,
    3163,  3165,  3166,  3169,  3172,  3174,  3178,  3183,  3187,  3191,
    3192,  3195,  3198,  3200,  3204,  3208,  3209,  3213,  3215,  3218,
    3220,  3222,  3224,  3226,  3228,  3230,  3232,  3234,  3236,  3238,
    3241,  3244,  3247,  3249,  3251,  3255,  3261,  3263,  3265,  3269,
    3274,  3280,  3282,  3286,  3289,  3291,  3295,  3298,  3300,  3302,
    3304,  3306,  3308,  3310,  3314,  3316,  3318,  3320,  3322,  3324,
    3326,  3328,  3330,  3332,  3334,  3336,  3338,  3340,  3342,  3344,
    3346,  3348,  3350,  3352,  3354,  3356,  3358,  3360,  3362,  3364,
    3366,  3368,  3370,  3372,  3374,  3376,  3378,  3380,  3382,  3384,
    3386,  3388,  3390,  3392,  3394,  3396,  3398,  3400,  3402,  3404,
    3406,  3408,  3410,  3412,  3414,  3416,  3418,  3420,  3422,  3424,
    3426,  3428,  3430,  3432,  3434,  3436,  3438,  3440,  3442,  3444,
    3446,  3448,  3450,  3452,  3454,  3456,  3458,  3460,  3462,  3464,
    3466,  3468,  3470,  3472,  3474,  3476,  3478,  3480,  3482,  3484,
    3486,  3488,  3490,  3492,  3494,  3496,  3498,  3500,  3502,  3504,
    3506,  3508,  3510,  3512,  3514,  3516,  3518,  3520,  3522,  3524,
    3526,  3528,  3530,  3532,  3534,  3536,  3538,  3540,  3542,  3544,
    3546,  3548,  3550,  3552,  3554,  3556,  3558,  3560,  3562,  3564,
    3566,  3568,  3570,  3572,  3574,  3576,  3578,  3580,  3582,  3584,
    3586,  3588,  3590,  3592,  3594,  3596,  3598,  3600,  3602,  3604,
    3606,  3608,  3610,  3612,  3614,  3616,  3618,  3620,  3622,  3624,
    3626,  3628,  3629,  3634,  3635,  3637,  3640,  3645,  3646,  3648,
    3650,  3652,  3653,  3655,  3657,  3659,  3660,  3663,  3666,  3669,
    3674,  3678,  3685,  3690,  3695,  3699,  3705,  3707,  3710,  3713,
    3716,  3718,  3720,  3725,  3727,  3729,  3731,  3733,  3734,  3739,
    3741,  3743,  3745,  3749,  3753,  3755,  3757,  3760,  3763,  3766,
    3771,  3775,  3776,  3784,  3786,  3789,  3791,  3793,  3795,  3797,
    3799,  3801,  3802,  3808,  3810,  3812,  3814,  3816,  3818,  3819,
    3827,  3828,  3838,  3840,  3843,  3845,  3847,  3851,  3852,  3856,
    3857,  3861,  3862,  3866,  3867,  3871,  3873,  3875,  3877,  3879,
    3881,  3883,  3885,  3887,  3889,  3891,  3893,  3896,  3899,  3901,
    3905,  3908,  3911,  3914,  3915,  3917,  3921,  3923,  3926,  3929,
    3932,  3934,  3938,  3942,  3944,  3946,  3950,  3955,  3961,  3963,
    3964,  3968,  3972,  3974,  3976,  3977,  3980,  3983,  3986,  3989,
    3990,  3993,  3996,  3998,  4001,  4004,  4007,  4010,  4011,  4015,
    4016,  4018,  4020,  4022,  4027,  4030,  4031,  4033,  4034,  4039,
    4041,  4043,  4044,  4045,  4049,  4050
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const short yyrhs[] =
{
     413,     0,    -1,     3,    -1,   414,     3,    -1,   485,    -1,
     512,    -1,   505,    -1,   766,    -1,   415,    -1,   514,    -1,
     769,    -1,   419,    -1,   650,    -1,   673,    -1,   611,    -1,
     613,    -1,   744,    -1,   619,    -1,   677,    -1,   691,    -1,
     728,    -1,   689,    -1,   519,    -1,   687,    -1,   521,    -1,
     507,    -1,   622,    -1,   683,    -1,   503,    -1,   742,    -1,
     770,    -1,   771,    -1,   525,    -1,   716,    -1,   498,    -1,
     499,    -1,   663,    -1,   661,    -1,   735,    -1,   734,    -1,
     646,    -1,   690,    -1,    -1,    28,    48,   243,   416,   417,
      -1,   418,    -1,   417,   406,   418,    -1,   163,     9,   242,
      -1,   164,     9,   242,    -1,   167,     9,   242,    -1,   165,
       9,   242,    -1,   168,     9,   602,    -1,   166,     9,   603,
      -1,   169,     9,   602,    -1,   171,     9,   242,    -1,   172,
       9,   602,    -1,    -1,    33,   432,   239,   435,   711,   420,
     423,    -1,    -1,    33,   480,   139,   712,   192,   711,   421,
     404,   481,   405,    -1,    33,   317,   435,   712,    -1,    -1,
      33,   444,   253,   712,   422,   251,   445,   252,   242,    -1,
     404,   424,    -1,   436,   426,    -1,   446,   405,   436,   426,
      -1,    -1,   429,   405,   425,   775,    -1,    -1,    -1,   695,
     431,   429,   427,   772,    -1,    -1,   695,   431,   404,   429,
     405,   428,   775,    -1,    -1,    60,   430,   533,   537,   443,
      -1,    -1,    76,    -1,    -1,   433,    -1,   434,    -1,   434,
     433,    -1,   240,    -1,    -1,   342,   187,   116,    -1,    -1,
     437,    -1,   438,    -1,   438,   437,    -1,   246,     9,   439,
      -1,   174,     9,   603,    -1,   181,     9,   603,    -1,    79,
       9,   602,    -1,   356,     9,   242,    -1,    30,     9,   242,
      -1,    78,     9,   603,    -1,   202,     9,   602,    -1,   202,
       9,   102,    -1,    92,     9,   602,    -1,   104,     9,   602,
      -1,   227,     9,   440,    -1,   211,     9,   441,    -1,   212,
       9,   602,    -1,   213,     9,   602,    -1,   255,     9,   404,
     615,   405,    -1,    91,   640,   712,    -1,   271,   229,   640,
     712,    -1,   343,     9,   442,    -1,   101,   114,     9,   242,
      -1,   139,   114,     9,   242,    -1,   147,    -1,   182,    -1,
     179,    -1,   133,    -1,   180,    -1,    81,    -1,   143,    -1,
     102,    -1,   120,    -1,   110,    -1,   268,    -1,   210,    -1,
     209,    -1,   602,    -1,   188,    -1,   119,    -1,     6,    -1,
      -1,   532,   536,    -1,    -1,    73,    -1,   294,    -1,   291,
      -1,   281,    -1,   447,    -1,   446,   406,   447,    -1,   448,
      -1,   449,    -1,   452,   450,    -1,   452,   472,    -1,   477,
     483,   404,   481,   405,    -1,   451,   123,   150,   483,   404,
     481,   405,   472,    -1,   451,   450,    -1,    -1,    93,   544,
      -1,    -1,    98,   483,    -1,    -1,   710,   453,   454,   468,
      -1,   459,   466,   463,    -1,   460,   467,   463,    -1,   280,
     461,   463,    -1,    83,   466,    -1,    84,    -1,   457,   404,
     190,   405,   471,    -1,   457,   471,    -1,    82,   404,   190,
     405,    -1,   458,   404,   190,   405,   471,    -1,   303,   404,
     190,   405,    -1,   381,   466,   463,    -1,   275,    -1,   297,
      -1,   296,    -1,   296,   404,   190,   405,    -1,   274,    -1,
     298,    -1,   270,    -1,   285,    -1,   283,    -1,   161,   303,
      -1,   161,   458,    -1,   300,    -1,   295,    -1,   287,    -1,
     284,    -1,   276,   461,   463,    -1,   288,   461,   463,    -1,
      -1,   278,   455,   404,   484,   405,    -1,    -1,   229,   456,
     404,   484,   405,    -1,   271,    -1,   186,    -1,   183,   271,
      -1,   457,   305,    -1,   304,    -1,   183,   304,    -1,   186,
     304,    -1,   281,    -1,   299,    -1,   293,    -1,   286,    -1,
     269,    -1,   291,    -1,   277,    -1,   277,   289,    -1,    -1,
     404,   190,   405,    -1,   462,    -1,   404,   190,   406,   190,
     405,    -1,    -1,   464,    -1,   464,   465,    -1,   465,    -1,
     292,    -1,   302,    -1,   306,    -1,    -1,   404,   190,   405,
      -1,    -1,   462,    -1,    -1,   469,    -1,   469,   470,    -1,
     470,    -1,   189,    -1,   187,   189,    -1,   102,   705,    -1,
      78,    -1,   204,   150,    -1,   256,    -1,   256,   150,    -1,
      30,   703,    -1,    -1,    82,    -1,   271,   229,   640,   712,
      -1,   216,   711,   473,    -1,   216,   711,   404,   481,   405,
     473,    -1,    -1,   474,    -1,   474,   475,    -1,   475,    -1,
     192,    36,   476,    -1,   192,    71,   476,    -1,   173,   125,
      -1,   173,   203,    -1,   224,    -1,    89,    -1,   229,   189,
      -1,   188,    72,    -1,   229,   102,    -1,   451,   204,   150,
      -1,   478,    -1,   126,    -1,   126,   478,    -1,   451,   256,
      -1,   451,   256,   478,    -1,   150,    -1,   139,    -1,   149,
      -1,   139,    -1,   140,    -1,    -1,   256,    -1,   126,    -1,
     481,   406,   482,   597,    -1,   482,   597,    -1,   712,    -1,
     712,   404,   190,   405,    -1,    -1,   710,    -1,   704,    -1,
     484,   406,   704,    -1,    -1,    23,   494,   239,   711,   486,
     487,    -1,    -1,   489,    -1,   487,   406,   489,    -1,    21,
     493,    -1,   488,   448,   496,    -1,    21,   449,    -1,   488,
     404,   446,   405,    -1,    -1,    28,   493,   710,   490,   452,
     496,    -1,    -1,    -1,   353,   493,   710,   491,   454,   468,
     492,   496,    -1,    38,   493,   710,   495,    -1,    38,   204,
     150,    -1,    38,   123,   150,   483,    -1,    38,   478,   710,
      -1,   108,   149,    -1,   111,   149,    -1,    23,   493,   710,
     229,   102,   705,    -1,    23,   493,   710,    38,   102,    -1,
     219,   497,   711,    -1,   437,    -1,   594,    -1,    -1,    96,
      -1,    -1,   138,    -1,    -1,   224,    -1,    89,    -1,    -1,
      22,   712,    -1,   119,    -1,    -1,   243,    -1,     9,    -1,
      76,    -1,    64,    62,   501,    -1,    66,    62,   501,    -1,
      62,    64,   501,    -1,    62,    66,   501,    -1,    -1,    64,
     245,   500,    -1,   502,    -1,   501,   406,   502,    -1,    -1,
      63,    -1,    43,    -1,    -1,   223,   730,   504,   615,   124,
     242,    -1,    -1,    80,   730,   506,   615,   243,   242,    -1,
      -1,    54,   730,   508,   615,   509,    -1,    -1,   510,    -1,
     511,    -1,   511,   510,    -1,   290,    -1,   117,    -1,   258,
      -1,    -1,    24,   730,   513,   615,   516,    -1,    -1,    93,
     730,   515,   615,   516,    -1,    -1,   517,    -1,   518,    -1,
     518,   517,    -1,   290,    -1,   279,    -1,   178,    -1,   117,
      -1,   272,    -1,    -1,    52,   730,   520,   615,   516,    -1,
      -1,   219,   730,   522,   523,    -1,   524,    -1,   523,   406,
     524,    -1,   711,   243,   711,    -1,   526,    -1,    -1,    60,
     529,   527,   772,    -1,    -1,   404,    60,   529,   405,   528,
     775,    -1,    -1,   530,   533,   537,   531,   536,    -1,   598,
      -1,   532,    -1,   609,   532,    -1,   532,   609,    -1,   124,
     569,   586,   590,   587,   593,   598,   604,    -1,    -1,   534,
      -1,   534,   535,    -1,   535,    -1,   236,    -1,   135,    -1,
     109,    -1,   390,    -1,   386,    -1,   391,    -1,   388,    -1,
     389,    -1,   387,    -1,    74,    -1,    -1,   335,    71,    -1,
      47,   145,   364,   352,    -1,   537,   406,   538,    -1,   538,
      -1,   398,    -1,   539,   541,   540,   542,    -1,    -1,    -1,
     707,    -1,   544,    -1,    -1,    76,   712,    -1,    76,   242,
      -1,   712,    -1,   242,    -1,    -1,   404,   405,    -1,   545,
      -1,   548,    -1,   544,   145,   404,   556,   405,    -1,   544,
     187,   145,   404,   556,   405,    -1,   544,   309,   547,    75,
     544,    -1,   544,   187,   309,   547,    75,   544,    -1,   544,
     197,   544,    -1,   544,   196,   544,    -1,   544,   267,   544,
      -1,   544,    75,   544,    -1,   544,   155,   548,   589,    -1,
     544,   187,   155,   548,   589,    -1,   544,   217,   544,    -1,
     544,   187,   217,   544,    -1,   544,    16,   189,    -1,   544,
      16,   187,   189,    -1,   544,     9,   544,    -1,   544,    10,
     544,    -1,   544,    11,   544,    -1,   544,    12,   544,    -1,
     544,    13,   544,    -1,   544,    14,   544,    -1,   544,    15,
     544,    -1,   544,    17,   544,    -1,   544,    18,   544,    -1,
     544,   397,   544,    -1,   544,   396,   544,    -1,   544,   398,
     544,    -1,   544,   399,   544,    -1,   544,   394,   544,    -1,
     544,   403,   544,    -1,   544,   395,   544,    -1,   544,   400,
     544,    -1,   544,   397,   344,   544,   582,    -1,   544,   396,
     344,   544,   582,    -1,   546,   309,   547,    75,   544,    -1,
     546,   187,   309,   547,    75,   544,    -1,   546,   197,   544,
      -1,   546,   196,   544,    -1,   546,   267,   544,    -1,   546,
      75,   544,    -1,   546,   155,   548,   589,    -1,   546,   187,
     155,   548,   589,    -1,   546,   217,   544,    -1,   546,   187,
     217,   544,    -1,   546,    16,   189,    -1,   546,    16,   187,
     189,    -1,   546,     9,   544,    -1,   546,    10,   544,    -1,
     546,    11,   544,    -1,   546,    12,   544,    -1,   546,    13,
     544,    -1,   546,    14,   544,    -1,   546,    15,   544,    -1,
     546,    17,   544,    -1,   546,    18,   544,    -1,   546,   397,
     544,    -1,   546,   396,   544,    -1,   546,   398,   544,    -1,
     546,   399,   544,    -1,   546,   394,   544,    -1,   546,   403,
     544,    -1,   546,   395,   544,    -1,   546,   400,   544,    -1,
     546,   397,   344,   544,   582,    -1,   546,   396,   344,   544,
     582,    -1,   548,    -1,   547,   145,   404,   556,   405,    -1,
     547,   187,   145,   404,   556,   405,    -1,   547,   309,   547,
      75,   544,    -1,   547,   187,   309,   547,    75,   544,    -1,
     547,   197,   544,    -1,   547,   196,   544,    -1,   547,   267,
     544,    -1,   547,   155,   548,   589,    -1,   547,   187,   155,
     548,   589,    -1,   547,   217,   544,    -1,   547,   187,   217,
     544,    -1,   547,    16,   189,    -1,   547,    16,   187,   189,
      -1,   547,     9,   544,    -1,   547,    10,   544,    -1,   547,
      11,   544,    -1,   547,    12,   544,    -1,   547,    13,   544,
      -1,   547,    14,   544,    -1,   547,    15,   544,    -1,   547,
      17,   544,    -1,   547,    18,   544,    -1,   547,   397,   544,
      -1,   547,   396,   544,    -1,   547,   398,   544,    -1,   547,
     399,   544,    -1,   547,   394,   544,    -1,   547,   403,   544,
      -1,   547,   395,   544,    -1,   547,   400,   544,    -1,   547,
     397,   344,   544,   582,    -1,   547,   396,   344,   544,   582,
      -1,   548,    -1,   709,    -1,   705,    -1,   410,   713,    19,
     544,    -1,   410,   713,    -1,   410,   410,   722,   713,    -1,
     550,    -1,   396,   544,    -1,   401,   544,    -1,   187,   544,
      -1,   407,   544,    -1,   404,   544,   405,    -1,   408,   712,
     544,   409,    -1,   173,   559,   307,   404,   544,   405,    -1,
     173,   559,   307,   404,   544,   145,    85,   352,   405,    -1,
      82,   544,    -1,    90,   404,   544,    76,   555,   405,    -1,
     312,   563,   378,   565,   564,   384,    -1,    99,   404,   544,
     406,   555,   405,    -1,   247,   404,   405,    -1,   248,   404,
     544,   405,    -1,   249,   404,   544,   406,   544,   405,    -1,
     250,   404,   544,   406,   544,   406,   544,   405,    -1,   308,
     404,   544,   405,    -1,   308,   404,   544,   406,   544,   405,
      -1,   271,   404,   556,   405,    -1,   273,   404,   556,   405,
      -1,   313,   404,   556,   405,    -1,   314,   404,   544,   406,
     556,   405,    -1,   315,   543,    -1,   316,   543,    -1,   316,
     404,   544,   405,    -1,   318,   404,   544,   406,   344,   544,
     582,   405,    -1,   319,   404,   544,   406,   344,   544,   582,
     405,    -1,   317,   404,   405,    -1,   328,   404,   544,   406,
     556,   405,    -1,   348,   404,   544,   406,   556,   405,    -1,
     330,   404,   544,   405,    -1,   330,   404,   544,   406,   544,
     405,    -1,   324,   404,   544,   406,   242,   405,    -1,   329,
     404,   544,   406,   242,   405,    -1,   326,   404,   544,   405,
      -1,   326,   404,   544,   406,   544,   405,    -1,   325,   404,
     544,   405,    -1,   325,   404,   544,   406,   544,   405,    -1,
     331,   404,   544,   406,   544,   406,   544,   405,    -1,   331,
     404,   544,   406,   544,   406,   544,   406,   544,   405,    -1,
     331,   404,   544,   406,   544,   406,   544,   406,   544,   406,
     544,   405,    -1,   334,   404,   544,   406,   190,   405,    -1,
     336,   404,   544,   405,    -1,   336,   404,   544,   406,   544,
     405,    -1,   333,   404,   544,   406,   556,   405,    -1,   340,
     404,   544,   405,    -1,   342,   404,   544,   406,   544,   406,
     544,   405,    -1,    42,   404,   544,   406,   544,   406,   544,
     406,   544,   405,    -1,   344,   544,   582,   397,   544,    -1,
     344,   404,   544,   406,   556,   405,    -1,   345,   404,   405,
      -1,   345,   404,   544,   405,    -1,   346,   404,   544,   406,
     544,   405,    -1,   347,   404,   544,   406,   544,   405,    -1,
     347,   404,   544,   406,   544,   406,   544,   405,    -1,   130,
     404,   544,   406,   556,   405,    -1,   152,   404,   544,   406,
     556,   405,    -1,   158,   404,   544,   405,    -1,   158,   404,
     544,   406,   544,   405,    -1,   349,   404,   544,   406,   544,
     405,    -1,   349,   404,   544,   406,   544,   406,   544,   405,
      -1,   351,   404,   544,   405,    -1,   354,   404,   544,   405,
      -1,   355,   543,    -1,   355,   404,   544,   405,    -1,   356,
     404,   544,   405,    -1,   357,   404,   546,   145,   544,   405,
      -1,   359,   404,   544,   405,    -1,   359,   404,   405,    -1,
     360,   404,   544,   406,   544,   406,   544,   405,    -1,   361,
     404,   544,   406,   544,   405,    -1,   362,   404,   544,   405,
      -1,   362,   404,   544,   406,   544,   405,    -1,   363,   404,
     544,   405,    -1,   365,   404,   544,   406,   544,   406,   544,
     405,    -1,   365,   404,   544,   406,   544,   405,    -1,   365,
     404,   544,   124,   544,   335,   544,   405,    -1,   365,   404,
     544,   124,   544,   405,    -1,   366,   404,   544,   406,   544,
     406,   544,   405,    -1,   367,   404,   544,   405,    -1,   367,
     404,   151,   568,   124,   544,   405,    -1,   367,   404,   244,
     568,   124,   544,   405,    -1,   367,   404,    86,   568,   124,
     544,   405,    -1,   367,   404,   544,   124,   544,   405,    -1,
      69,   404,   544,   406,   544,   405,    -1,   368,   404,   549,
     405,    -1,   369,   404,   549,   405,    -1,   370,   404,   549,
     405,    -1,   371,   404,   549,   405,    -1,   372,   404,   549,
     405,    -1,   373,   404,   549,   405,    -1,   374,   404,   703,
     406,   190,   406,   190,   406,   556,   405,    -1,   375,   404,
     405,    -1,   375,   404,   544,   405,    -1,   376,   404,   405,
      -1,   377,   404,   544,   405,    -1,   377,   404,   544,   406,
     544,   405,    -1,   381,   404,   544,   405,    -1,   382,   404,
     544,   405,    -1,   382,   404,   544,   406,   544,   405,    -1,
     383,   404,   602,   406,   544,   405,    -1,   332,   404,   582,
     124,   544,   405,    -1,    -1,   556,    -1,    25,   404,   553,
     405,    -1,   310,   404,   553,   405,    -1,   311,   404,   553,
     405,    -1,    32,   404,   585,   398,   405,    -1,    32,   404,
     553,   405,    -1,    -1,    -1,    32,   404,   109,   551,   556,
     552,   405,    -1,   337,   404,   703,   406,   190,   406,   190,
     406,   553,   405,    -1,    50,   404,   553,   405,    -1,    49,
     404,   553,   405,    -1,    65,   404,   553,   405,    -1,    67,
     404,   553,   405,    -1,    -1,   585,   554,   544,    -1,    82,
      -1,   271,    -1,   292,    -1,   292,   281,    -1,   302,    -1,
     302,   281,    -1,   275,    -1,   297,    -1,   274,    -1,    -1,
     557,   558,    -1,   544,    -1,   558,   406,   544,    -1,   560,
      -1,   404,   560,   405,    -1,    -1,   561,   562,    -1,   709,
      -1,   562,   406,   709,    -1,    -1,   544,    -1,    -1,   327,
     544,    -1,    -1,   566,   567,    -1,   544,   385,   544,    -1,
     567,   378,   544,   385,   544,    -1,    -1,   544,    -1,   404,
     569,   405,    -1,   574,    -1,   569,   406,   569,    -1,   569,
     573,   569,    -1,   569,   236,   569,    -1,   569,   573,   569,
     192,   544,    -1,    -1,   569,   573,   569,   260,   570,   404,
     581,   405,    -1,   569,   346,   576,   148,   569,   192,   544,
      -1,    -1,   569,   346,   576,   148,   569,   571,   260,   404,
     581,   405,    -1,   569,   184,   346,   576,   148,   569,    -1,
     569,   361,   576,   148,   569,   192,   544,    -1,    -1,   569,
     361,   576,   148,   569,   572,   260,   404,   581,   405,    -1,
     569,   184,   361,   576,   148,   569,    -1,   569,   184,   148,
     569,    -1,   148,    -1,   142,   148,    -1,    34,   148,    -1,
      -1,   575,   711,   584,   577,    -1,   408,   712,   574,   346,
     199,   148,   574,   192,   544,   409,    -1,    -1,   199,    -1,
      -1,   259,   578,    -1,   122,   578,    -1,   138,   578,    -1,
      -1,   478,   579,   404,   580,   405,    -1,   580,   406,   712,
      -1,   712,    -1,   204,    -1,   712,    -1,   581,   406,   712,
      -1,   320,    -1,   321,    -1,   322,    -1,   323,    -1,   338,
      -1,   339,    -1,   340,    -1,   350,    -1,   351,    -1,   354,
      -1,   363,    -1,   380,    -1,   381,    -1,    -1,    76,    -1,
       9,    -1,    -1,   583,   712,    -1,    -1,    74,    -1,    -1,
     263,   544,    -1,    -1,    -1,   132,   588,   544,    -1,   115,
     242,    -1,    -1,    -1,   131,    87,   591,   592,    -1,   591,
     406,   708,   597,    -1,   708,   597,    -1,    -1,   264,    35,
      -1,   264,    58,    -1,    -1,   594,    -1,    -1,   198,    87,
     595,   596,    -1,   596,   406,   708,   597,    -1,   708,   597,
      -1,    -1,    77,    -1,   105,    -1,    -1,    -1,   282,   599,
     600,    -1,   602,    -1,   602,   406,   602,    -1,   602,   191,
     602,    -1,    -1,   282,   603,    -1,   190,    -1,   160,    -1,
     301,    -1,   215,    -1,   121,    -1,   190,    -1,   301,    -1,
     160,    -1,   215,    -1,   121,    -1,    -1,    -1,   358,   712,
     605,   404,   606,   405,    -1,    -1,   607,    -1,   607,   406,
     608,    -1,   608,    -1,   539,   544,    -1,    -1,   144,   200,
     242,   610,   696,   699,    -1,   144,   201,   242,    -1,    -1,
      37,   612,   644,    -1,    38,   618,   239,   617,   615,   495,
      -1,    -1,    38,   139,   712,   192,   711,   614,    -1,    38,
     317,   617,   712,    -1,    38,   253,   712,    -1,   616,    -1,
     615,   406,   616,    -1,   711,    -1,    -1,   342,   116,    -1,
      -1,   240,    -1,    -1,    -1,    42,   620,   625,   494,   627,
     621,   629,    -1,    -1,    -1,   360,   623,   626,   627,   624,
     629,    -1,    -1,   162,    -1,   103,    -1,   135,    -1,   649,
      -1,   103,    -1,   144,   628,    -1,   628,    -1,   616,    -1,
     633,    -1,   404,   405,   633,    -1,   404,   632,   405,   633,
      -1,    -1,   229,   630,   637,    -1,    -1,   404,   632,   405,
      -1,   404,   405,    -1,   632,   406,   706,    -1,   706,    -1,
     261,   636,    -1,    -1,   429,   634,   772,    -1,    -1,   404,
     429,   405,   635,   775,    -1,   636,   406,   641,    -1,   641,
      -1,   637,   406,   638,    -1,   638,    -1,   709,   639,   645,
      -1,     9,    -1,    19,    -1,    -1,   639,    -1,    -1,   404,
     642,   643,   405,    -1,    -1,   644,    -1,   644,   406,   645,
      -1,   645,    -1,   544,    -1,   102,    -1,    -1,    71,   647,
     649,   494,   569,   229,   648,   586,   593,   601,    -1,   648,
     406,   709,   639,   544,    -1,   709,   639,   544,    -1,    -1,
     162,    -1,    -1,    36,   651,   659,   652,    -1,    -1,   124,
     711,   653,   586,   593,   601,    -1,    -1,   656,   654,   124,
     569,   586,    -1,    -1,   124,   656,   655,   260,   569,   586,
      -1,   657,    -1,   656,   406,   657,    -1,   712,   658,    -1,
     712,   411,   712,   658,    -1,    -1,   411,   398,    -1,    -1,
     660,   659,    -1,   290,    -1,   162,    -1,    69,   662,   616,
      -1,    -1,   239,    -1,    -1,    61,   664,   665,    -1,   100,
     668,    -1,   238,   667,   668,    -1,   239,   235,   667,   668,
      -1,   193,   238,   667,   668,    -1,   669,    95,   670,   711,
     667,   668,    -1,   185,    48,   335,    62,   264,   165,     9,
     242,    75,   166,     9,   603,    75,   170,     9,   602,    -1,
      48,   159,    -1,    62,   136,    -1,    -1,    27,    39,   671,
     672,   666,   598,    -1,   479,   124,   711,   667,    -1,   235,
     668,    -1,   143,   235,    -1,   669,   207,    -1,   721,   262,
     668,    -1,   159,    -1,   129,   335,   714,    -1,    33,   239,
     711,    -1,    48,   235,    -1,    62,   235,    -1,    -1,   670,
     712,    -1,    -1,   155,   704,    -1,    -1,   125,    -1,   124,
      -1,   145,    -1,    -1,   145,   242,    -1,    -1,   124,   603,
      -1,    -1,   675,   711,   674,   676,    -1,   675,   525,    -1,
     105,    -1,   106,    -1,    -1,   704,    -1,   712,    -1,    -1,
      41,   678,   679,    -1,   679,   406,   680,    -1,   680,    -1,
      -1,   730,   681,   682,    -1,   238,   264,   214,    47,    -1,
     208,    88,    -1,   136,    -1,   205,    -1,   159,    -1,   235,
      -1,    62,    -1,    48,    -1,   107,    -1,   222,    -1,    -1,
     615,    -1,    -1,    56,   684,   685,    -1,   685,   406,   686,
      -1,   686,    -1,    62,    -1,    48,    -1,   208,    88,    -1,
      -1,    53,   688,    48,   159,   243,   242,    -1,    44,   544,
      -1,   259,   712,    -1,    -1,    45,   101,   694,   693,   141,
     242,   692,   695,   144,   239,   711,   696,   699,   702,   631,
      -1,    45,   239,   711,   124,    48,    -1,    45,   101,   124,
      48,    -1,    -1,   157,    -1,    -1,    97,    -1,   162,    -1,
      -1,   360,    -1,   138,    -1,    -1,    95,   697,    -1,   697,
     698,    -1,   698,    -1,   241,    87,   704,    -1,   195,   112,
      87,   704,    -1,   112,    87,   704,    -1,   113,    87,   704,
      -1,    -1,   156,   700,    -1,   700,   701,    -1,   701,    -1,
     241,    87,   704,    -1,   234,    87,   704,    -1,    -1,   138,
     190,   156,    -1,   242,    -1,   703,   242,    -1,   242,    -1,
     134,    -1,   703,    -1,   190,    -1,   160,    -1,   301,    -1,
     215,    -1,   121,    -1,   189,    -1,   134,    -1,   275,   703,
      -1,   297,   703,    -1,   296,   703,    -1,   709,    -1,   707,
      -1,   712,   411,   398,    -1,   712,   411,   712,   411,   398,
      -1,   544,    -1,   712,    -1,   712,   411,   712,    -1,   411,
     712,   411,   712,    -1,   712,   411,   712,   411,   712,    -1,
     712,    -1,   712,   411,   712,    -1,   411,   712,    -1,   712,
      -1,   712,   411,   712,    -1,   411,   712,    -1,   137,    -1,
     715,    -1,   712,    -1,   242,    -1,   154,    -1,   713,    -1,
     713,   410,   713,    -1,    72,    -1,    22,    -1,   307,    -1,
      73,    -1,    78,    -1,    79,    -1,    25,    -1,    80,    -1,
      26,    -1,    81,    -1,    27,    -1,    83,    -1,    84,    -1,
      85,    -1,    88,    -1,   272,    -1,    91,    -1,    92,    -1,
     393,    -1,    29,    -1,     4,    -1,    30,    -1,    94,    -1,
      31,    -1,   268,    -1,    97,    -1,    35,    -1,   101,    -1,
     274,    -1,   275,    -1,   323,    -1,   104,    -1,   107,    -1,
     114,    -1,    37,    -1,   201,    -1,   110,    -1,   384,    -1,
     278,    -1,   115,    -1,    39,    -1,    40,    -1,   117,    -1,
     279,    -1,   108,    -1,   111,    -1,   125,    -1,   118,    -1,
     119,    -1,   120,    -1,    41,    -1,   129,    -1,   127,    -1,
     133,    -1,     5,    -1,   136,    -1,   340,    -1,   341,    -1,
     140,    -1,   146,    -1,   147,    -1,   392,    -1,   143,    -1,
     343,    -1,    43,    -1,     6,    -1,   153,    -1,   157,    -1,
      46,    -1,   159,    -1,   174,    -1,    48,    -1,   163,    -1,
     168,    -1,   165,    -1,   166,    -1,   164,    -1,   167,    -1,
     169,    -1,   175,    -1,   176,    -1,   177,    -1,   178,    -1,
     179,    -1,   180,    -1,   351,    -1,   181,    -1,   353,    -1,
     352,    -1,   354,    -1,   182,    -1,   183,    -1,   186,    -1,
       7,    -1,   185,    -1,   188,    -1,    51,    -1,   191,    -1,
     193,    -1,   202,    -1,   356,    -1,     8,    -1,   206,    -1,
     207,    -1,   208,    -1,   290,    -1,   209,    -1,   212,    -1,
     213,    -1,   210,    -1,   211,    -1,   171,    -1,   172,    -1,
     218,    -1,    54,    -1,   220,    -1,    55,    -1,    56,    -1,
     222,    -1,   223,    -1,    57,    -1,    58,    -1,   226,    -1,
     227,    -1,   228,    -1,    59,    -1,   363,    -1,   230,    -1,
     231,    -1,   292,    -1,   364,    -1,   232,    -1,    62,    -1,
     387,    -1,   391,    -1,   389,    -1,    63,    -1,    64,    -1,
     235,    -1,    66,    -1,   294,    -1,   237,    -1,    68,    -1,
     240,    -1,   295,    -1,   245,    -1,    69,    -1,   296,    -1,
     297,    -1,   246,    -1,   253,    -1,   254,    -1,   258,    -1,
     262,    -1,   379,    -1,   266,    -1,   381,    -1,    -1,   229,
     718,   717,   719,    -1,    -1,   194,    -1,   720,   723,    -1,
     719,   406,   720,   723,    -1,    -1,   127,    -1,   157,    -1,
     231,    -1,    -1,   157,    -1,   231,    -1,   127,    -1,    -1,
     157,   411,    -1,   231,   411,    -1,   127,   411,    -1,   410,
     713,   639,   544,    -1,   724,   639,   727,    -1,   410,   410,
     722,   724,   639,   727,    -1,   245,   146,   153,   725,    -1,
     271,   229,   640,   727,    -1,   356,   639,   726,    -1,   356,
     335,   714,   639,   726,    -1,   712,    -1,   214,   254,    -1,
     214,    94,    -1,   220,   214,    -1,   230,    -1,   242,    -1,
     356,   404,   242,   405,    -1,   544,    -1,   102,    -1,   192,
      -1,    74,    -1,    -1,    47,   730,   729,   731,    -1,   239,
      -1,   238,    -1,   732,    -1,   731,   406,   732,    -1,   711,
     584,   733,    -1,   214,    -1,   265,    -1,   162,   265,    -1,
     214,   157,    -1,    70,   730,    -1,     5,   711,   193,   584,
      -1,     5,   711,     4,    -1,    -1,     5,   711,   214,   736,
     737,   586,   598,    -1,   738,    -1,   712,   739,    -1,   119,
      -1,     7,    -1,   119,    -1,     7,    -1,     8,    -1,     6,
      -1,    -1,   741,   740,   404,   644,   405,    -1,     9,    -1,
      11,    -1,    13,    -1,    12,    -1,    14,    -1,    -1,   225,
     743,   746,   192,   756,   124,   757,    -1,    -1,   128,   745,
     746,   192,   756,   243,   757,   762,   763,    -1,   747,    -1,
      74,   205,    -1,    74,    -1,   748,    -1,   747,   406,   748,
      -1,    -1,    60,   749,   759,    -1,    -1,    42,   750,   759,
      -1,    -1,    71,   751,   759,    -1,    -1,   216,   752,   759,
      -1,    36,    -1,   257,    -1,   139,    -1,    23,    -1,    33,
      -1,    38,    -1,    40,    -1,   218,    -1,   232,    -1,   206,
      -1,   118,    -1,   128,   194,    -1,    61,   100,    -1,    68,
      -1,    33,   240,   238,    -1,    47,   238,    -1,    55,    62,
      -1,    55,    29,    -1,    -1,    75,    -1,   755,   753,   754,
      -1,   755,    -1,   237,   242,    -1,   392,   242,    -1,   393,
     242,    -1,   398,    -1,   712,   411,   398,    -1,   398,   411,
     398,    -1,   711,    -1,   758,    -1,   757,   406,   758,    -1,
     714,   341,    87,   242,    -1,   714,   341,    87,   356,   242,
      -1,   714,    -1,    -1,   404,   760,   405,    -1,   760,   406,
     761,    -1,   761,    -1,   712,    -1,    -1,   221,   754,    -1,
     221,   233,    -1,   221,   266,    -1,   221,    51,    -1,    -1,
     264,   764,    -1,   764,   765,    -1,   765,    -1,   128,   194,
      -1,   176,   602,    -1,   177,   602,    -1,   175,   602,    -1,
      -1,    26,   767,   768,    -1,    -1,   379,    -1,    31,    -1,
      57,    -1,    57,   243,    59,   712,    -1,    59,   712,    -1,
      -1,   773,    -1,    -1,   255,   778,   774,   526,    -1,   773,
      -1,   776,    -1,    -1,    -1,   777,   593,   598,    -1,    -1,
      74,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short yyrline[] =
{
       0,   609,   609,   624,   626,   628,   629,   630,   631,   632,
     633,   634,   635,   636,   637,   638,   639,   640,   641,   642,
     643,   644,   645,   646,   647,   648,   649,   650,   651,   652,
     653,   654,   655,   656,   657,   658,   659,   660,   661,   662,
     663,   664,   670,   668,   679,   681,   683,   688,   693,   698,
     703,   708,   725,   730,   735,   748,   746,   767,   766,   783,
     791,   790,   805,   807,   809,   811,   811,   814,   817,   816,
     819,   818,   824,   822,   838,   840,   842,   844,   846,   848,
     850,   853,   855,   857,   859,   861,   863,   865,   867,   868,
     869,   870,   871,   872,   873,   874,   875,   876,   877,   878,
     879,   880,   881,   894,   895,   896,   897,   898,   900,   902,
     903,   904,   905,   906,   907,   909,   911,   912,   913,   915,
     917,   918,   920,   922,   923,   925,   927,   929,   931,   933,
     935,   936,   938,   940,   943,   945,   948,   950,   956,   963,
     967,   973,   975,   978,   980,   984,   982,  1000,  1002,  1003,
    1004,  1006,  1008,  1010,  1012,  1015,  1017,  1020,  1021,  1022,
    1023,  1024,  1026,  1027,  1029,  1031,  1033,  1035,  1037,  1038,
    1039,  1040,  1041,  1042,  1044,  1046,  1046,  1052,  1052,  1059,
    1061,  1062,  1064,  1066,  1067,  1068,  1070,  1072,  1073,  1074,
    1075,  1077,  1080,  1081,  1084,  1086,  1087,  1089,  1096,  1098,
    1100,  1102,  1104,  1106,  1107,  1109,  1111,  1113,  1115,  1117,
    1119,  1121,  1123,  1125,  1127,  1128,  1129,  1130,  1131,  1132,
    1133,  1135,  1137,  1138,  1141,  1143,  1148,  1150,  1152,  1154,
    1157,  1159,  1160,  1161,  1163,  1165,  1166,  1167,  1168,  1170,
    1172,  1173,  1174,  1175,  1176,  1178,  1180,  1182,  1184,  1185,
    1187,  1189,  1190,  1192,  1194,  1196,  1198,  1200,  1202,  1204,
    1206,  1214,  1212,  1240,  1241,  1242,  1244,  1247,  1249,  1250,
    1252,  1251,  1258,  1265,  1257,  1275,  1281,  1286,  1287,  1294,
    1295,  1296,  1302,  1308,  1314,  1315,  1317,  1319,  1321,  1323,
    1325,  1327,  1328,  1330,  1332,  1333,  1335,  1337,  1338,  1339,
    1344,  1351,  1358,  1365,  1374,  1373,  1378,  1380,  1382,  1384,
    1385,  1390,  1388,  1400,  1398,  1410,  1408,  1419,  1421,  1423,
    1425,  1427,  1429,  1430,  1434,  1432,  1445,  1443,  1454,  1456,
    1458,  1460,  1462,  1464,  1465,  1466,  1467,  1471,  1469,  1482,
    1480,  1489,  1491,  1493,  1506,  1510,  1509,  1512,  1511,  1516,
    1515,  1523,  1525,  1526,  1527,  1529,  1533,  1535,  1537,  1539,
    1541,  1543,  1549,  1550,  1551,  1552,  1558,  1564,  1565,  1569,
    1572,  1574,  1582,  1592,  1594,  1595,  1602,  1613,  1616,  1619,
    1621,  1623,  1625,  1626,  1627,  1628,  1630,  1632,  1635,  1636,
    1639,  1642,  1644,  1646,  1648,  1649,  1650,  1651,  1652,  1653,
    1654,  1655,  1656,  1657,  1658,  1659,  1660,  1661,  1662,  1663,
    1664,  1665,  1666,  1667,  1668,  1669,  1670,  1671,  1672,  1673,
    1674,  1675,  1677,  1681,  1684,  1686,  1687,  1688,  1689,  1690,
    1691,  1692,  1693,  1694,  1695,  1696,  1697,  1698,  1699,  1700,
    1701,  1702,  1703,  1704,  1705,  1706,  1707,  1708,  1709,  1710,
    1711,  1712,  1713,  1715,  1717,  1720,  1723,  1725,  1727,  1729,
    1730,  1731,  1732,  1733,  1734,  1735,  1736,  1737,  1738,  1739,
    1740,  1741,  1742,  1743,  1744,  1745,  1746,  1747,  1748,  1749,
    1750,  1751,  1752,  1753,  1754,  1755,  1757,  1759,  1761,  1763,
    1764,  1769,  1774,  1779,  1780,  1781,  1782,  1783,  1784,  1785,
    1786,  1789,  1792,  1793,  1794,  1796,  1797,  1799,  1801,  1803,
    1805,  1807,  1809,  1811,  1813,  1815,  1817,  1819,  1821,  1826,
    1828,  1830,  1835,  1837,  1839,  1844,  1845,  1847,  1849,  1851,
    1853,  1855,  1857,  1859,  1861,  1863,  1865,  1867,  1871,  1873,
    1875,  1877,  1879,  1882,  1884,  1890,  1895,  1897,  1899,  1901,
    1903,  1905,  1907,  1909,  1914,  1919,  1921,  1923,  1925,  1927,
    1931,  1933,  1935,  1937,  1939,  1941,  1943,  1944,  1946,  1948,
    1950,  1952,  1954,  1956,  1958,  1960,  1962,  1964,  1966,  1968,
    1975,  1982,  1989,  1996,  2003,  2010,  2014,  2019,  2021,  2023,
    2029,  2031,  2033,  2035,  2037,  2042,  2045,  2047,  2049,  2052,
    2054,  2056,  2058,  2061,  2063,  2060,  2066,  2068,  2070,  2072,
    2074,  2079,  2077,  2086,  2088,  2089,  2090,  2091,  2092,  2093,
    2094,  2095,  2099,  2098,  2103,  2105,  2107,  2109,  2112,  2111,
    2116,  2118,  2120,  2122,  2124,  2126,  2129,  2128,  2133,  2140,
    2147,  2149,  2151,  2153,  2154,  2155,  2156,  2158,  2162,  2160,
    2170,  2173,  2172,  2180,  2186,  2189,  2188,  2196,  2202,  2205,
    2207,  2208,  2212,  2211,  2225,  2228,  2230,  2232,  2234,  2240,
    2247,  2256,  2255,  2259,  2262,  2264,  2267,  2274,  2281,  2283,
    2284,  2285,  2286,  2287,  2288,  2289,  2290,  2291,  2292,  2293,
    2294,  2296,  2298,  2299,  2301,  2303,  2306,  2308,  2311,  2313,
    2321,  2323,  2323,  2333,  2335,  2342,  2344,  2346,  2349,  2352,
    2354,  2360,  2372,  2374,  2378,  2376,  2390,  2393,  2396,  2398,
    2399,  2402,  2405,  2404,  2418,  2425,  2431,  2439,  2445,  2448,
    2450,  2451,  2452,  2453,  2455,  2457,  2458,  2459,  2460,  2462,
    2465,  2464,  2477,  2479,  2481,  2483,  2485,  2497,  2495,  2504,
    2517,  2516,  2531,  2539,  2539,  2549,  2556,  2564,  2566,  2568,
    2572,  2574,  2577,  2579,  2586,  2588,  2585,  2598,  2604,  2596,
    2612,  2614,  2615,  2616,  2619,  2621,  2623,  2625,  2627,  2636,
    2638,  2639,  2641,  2640,  2649,  2651,  2652,  2654,  2656,  2658,
    2660,  2660,  2661,  2661,  2664,  2666,  2668,  2670,  2673,  2682,
    2683,  2686,  2688,  2693,  2691,  2704,  2706,  2708,  2714,  2721,
    2723,  2730,  2728,  2744,  2750,  2756,  2758,  2764,  2762,  2777,
    2775,  2785,  2784,  2788,  2787,  2793,  2795,  2797,  2804,  2813,
    2815,  2818,  2820,  2822,  2824,  2826,  2838,  2840,  2844,  2844,
    2848,  2851,  2857,  2864,  2871,  2879,  2889,  2893,  2898,  2897,
    2904,  2912,  2914,  2916,  2918,  2924,  2926,  2933,  2939,  2943,
    2948,  2950,  2952,  2954,  2956,  2958,  2960,  2962,  2964,  2966,
    2968,  2970,  2976,  2974,  2985,  2989,  2991,  2993,  2995,  2996,
    3004,  3002,  3012,  3014,  3017,  3016,  3018,  3019,  3020,  3021,
    3022,  3023,  3024,  3025,  3026,  3027,  3029,  3031,  3035,  3033,
    3042,  3044,  3046,  3048,  3049,  3053,  3051,  3065,  3080,  3089,
    3088,  3104,  3112,  3118,  3120,  3122,  3124,  3125,  3128,  3130,
    3131,  3133,  3135,  3137,  3139,  3141,  3143,  3149,  3150,  3152,
    3154,  3156,  3158,  3160,  3162,  3164,  3166,  3171,  3173,  3176,
    3178,  3184,  3186,  3187,  3188,  3189,  3190,  3191,  3193,  3194,
    3195,  3196,  3202,  3204,  3206,  3208,  3212,  3215,  3221,  3226,
    3231,  3238,  3240,  3241,  3243,  3245,  3246,  3249,  3251,  3261,
    3263,  3264,  3266,  3273,  3282,  3284,  3285,  3286,  3287,  3288,
    3289,  3290,  3291,  3292,  3293,  3294,  3295,  3296,  3297,  3298,
    3299,  3300,  3301,  3302,  3303,  3304,  3305,  3306,  3307,  3308,
    3309,  3310,  3311,  3312,  3313,  3314,  3315,  3316,  3317,  3318,
    3319,  3320,  3321,  3322,  3323,  3324,  3325,  3326,  3327,  3328,
    3329,  3330,  3331,  3332,  3333,  3334,  3335,  3336,  3337,  3338,
    3339,  3340,  3341,  3342,  3343,  3344,  3345,  3346,  3347,  3348,
    3349,  3350,  3351,  3352,  3353,  3354,  3355,  3356,  3357,  3358,
    3359,  3360,  3361,  3362,  3363,  3364,  3365,  3366,  3367,  3368,
    3369,  3370,  3371,  3372,  3373,  3374,  3375,  3376,  3377,  3378,
    3379,  3380,  3381,  3382,  3383,  3384,  3385,  3386,  3387,  3388,
    3389,  3390,  3391,  3392,  3393,  3394,  3395,  3396,  3397,  3398,
    3399,  3400,  3401,  3402,  3403,  3404,  3405,  3406,  3407,  3408,
    3409,  3410,  3411,  3412,  3413,  3414,  3415,  3416,  3417,  3418,
    3419,  3420,  3421,  3422,  3423,  3424,  3425,  3426,  3427,  3428,
    3429,  3430,  3431,  3432,  3433,  3434,  3435,  3436,  3437,  3438,
    3439,  3445,  3443,  3455,  3457,  3459,  3461,  3463,  3465,  3466,
    3467,  3470,  3472,  3473,  3474,  3477,  3479,  3480,  3481,  3484,
    3489,  3494,  3499,  3506,  3513,  3523,  3529,  3539,  3541,  3542,
    3543,  3546,  3548,  3561,  3563,  3564,  3565,  3573,  3571,  3580,
    3582,  3584,  3586,  3588,  3592,  3594,  3595,  3596,  3598,  3606,
    3613,  3620,  3619,  3631,  3633,  3635,  3637,  3639,  3641,  3642,
    3643,  3645,  3644,  3653,  3655,  3656,  3657,  3658,  3664,  3662,
    3681,  3679,  3697,  3699,  3700,  3702,  3704,  3707,  3706,  3708,
    3708,  3709,  3709,  3710,  3710,  3711,  3712,  3713,  3714,  3715,
    3716,  3717,  3718,  3719,  3720,  3721,  3722,  3723,  3724,  3725,
    3726,  3727,  3728,  3732,  3734,  3737,  3739,  3742,  3753,  3763,
    3775,  3788,  3800,  3812,  3822,  3824,  3832,  3847,  3849,  3853,
    3859,  3861,  3863,  3865,  3885,  3886,  3890,  3894,  3898,  3904,
    3906,  3908,  3910,  3912,  3914,  3919,  3924,  3931,  3930,  3934,
    3936,  3938,  3941,  3946,  3951,  3963,  3965,  3969,  3967,  3989,
    3991,  3993,  3999,  3998,  4015,  4017
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "END_OF_INPUT", "CLOSE_SYM", "HANDLER_SYM", 
  "LAST_SYM", "NEXT_SYM", "PREV_SYM", "EQ", "EQUAL_SYM", "GE", "GT_SYM", 
  "LE", "LT", "NE", "IS", "SHIFT_LEFT", "SHIFT_RIGHT", "SET_VAR", 
  "ABORT_SYM", "ADD", "AFTER_SYM", "ALTER", "ANALYZE_SYM", "AVG_SYM", 
  "BEGIN_SYM", "BINLOG_SYM", "CHANGE", "CLIENT_SYM", "COMMENT_SYM", 
  "COMMIT_SYM", "COUNT_SYM", "CREATE", "CROSS", "CUBE_SYM", "DELETE_SYM", 
  "DO_SYM", "DROP", "EVENTS_SYM", "EXECUTE_SYM", "FLUSH_SYM", "INSERT", 
  "IO_THREAD", "KILL_SYM", "LOAD", "LOCKS_SYM", "LOCK_SYM", "MASTER_SYM", 
  "MAX_SYM", "MIN_SYM", "NONE_SYM", "OPTIMIZE", "PURGE", "REPAIR", 
  "REPLICATION", "RESET_SYM", "ROLLBACK_SYM", "ROLLUP_SYM", 
  "SAVEPOINT_SYM", "SELECT_SYM", "SHOW", "SLAVE", "SQL_THREAD", 
  "START_SYM", "STD_SYM", "STOP_SYM", "SUM_SYM", "SUPER_SYM", 
  "TRUNCATE_SYM", "UNLOCK_SYM", "UPDATE_SYM", "ACTION", "AGGREGATE_SYM", 
  "ALL", "AND", "AS", "ASC", "AUTO_INC", "AVG_ROW_LENGTH", "BACKUP_SYM", 
  "BERKELEY_DB_SYM", "BINARY", "BIT_SYM", "BOOL_SYM", "BOOLEAN_SYM", 
  "BOTH", "BY", "CACHE_SYM", "CASCADE", "CAST_SYM", "CHARSET", 
  "CHECKSUM_SYM", "CHECK_SYM", "COMMITTED_SYM", "COLUMNS", "COLUMN_SYM", 
  "CONCURRENT", "CONSTRAINT", "CONVERT_SYM", "DATABASES", "DATA_SYM", 
  "DEFAULT", "DELAYED_SYM", "DELAY_KEY_WRITE_SYM", "DESC", "DESCRIBE", 
  "DES_KEY_FILE", "DISABLE_SYM", "DISTINCT", "DYNAMIC_SYM", "ENABLE_SYM", 
  "ENCLOSED", "ESCAPED", "DIRECTORY_SYM", "ESCAPE_SYM", "EXISTS", 
  "EXTENDED_SYM", "FILE_SYM", "FIRST_SYM", "FIXED_SYM", "FLOAT_NUM", 
  "FORCE_SYM", "FOREIGN", "FROM", "FULL", "FULLTEXT_SYM", "GLOBAL_SYM", 
  "GRANT", "GRANTS", "GREATEST_SYM", "GROUP", "HAVING", "HEAP_SYM", 
  "HEX_NUM", "HIGH_PRIORITY", "HOSTS_SYM", "IDENT", "IGNORE_SYM", "INDEX", 
  "INDEXES", "INFILE", "INNER_SYM", "INNOBASE_SYM", "INTO", "IN_SYM", 
  "ISOLATION", "ISAM_SYM", "JOIN_SYM", "KEYS", "KEY_SYM", "LEADING", 
  "LEAST_SYM", "LEVEL_SYM", "LEX_HOSTNAME", "LIKE", "LINES", "LOCAL_SYM", 
  "LOG_SYM", "LOGS_SYM", "LONG_NUM", "LONG_SYM", "LOW_PRIORITY", 
  "MASTER_HOST_SYM", "MASTER_USER_SYM", "MASTER_LOG_FILE_SYM", 
  "MASTER_LOG_POS_SYM", "MASTER_PASSWORD_SYM", "MASTER_PORT_SYM", 
  "MASTER_CONNECT_RETRY_SYM", "MASTER_SERVER_ID_SYM", 
  "RELAY_LOG_FILE_SYM", "RELAY_LOG_POS_SYM", "MATCH", "MAX_ROWS", 
  "MAX_CONNECTIONS_PER_HOUR", "MAX_QUERIES_PER_HOUR", 
  "MAX_UPDATES_PER_HOUR", "MEDIUM_SYM", "MERGE_SYM", "MEMORY_SYM", 
  "MIN_ROWS", "MYISAM_SYM", "NATIONAL_SYM", "NATURAL", "NEW_SYM", 
  "NCHAR_SYM", "NOT", "NO_SYM", "NULL_SYM", "NUM", "OFFSET_SYM", "ON", 
  "OPEN_SYM", "OPTION", "OPTIONALLY", "OR", "OR_OR_CONCAT", "ORDER_SYM", 
  "OUTER", "OUTFILE", "DUMPFILE", "PACK_KEYS_SYM", "PARTIAL", 
  "PRIMARY_SYM", "PRIVILEGES", "PROCESS", "PROCESSLIST_SYM", "QUERY_SYM", 
  "RAID_0_SYM", "RAID_STRIPED_SYM", "RAID_TYPE", "RAID_CHUNKS", 
  "RAID_CHUNKSIZE", "READ_SYM", "REAL_NUM", "REFERENCES", "REGEXP", 
  "RELOAD", "RENAME", "REPEATABLE_SYM", "REQUIRE_SYM", "RESOURCES", 
  "RESTORE_SYM", "RESTRICT", "REVOKE", "ROWS_SYM", "ROW_FORMAT_SYM", 
  "ROW_SYM", "SET", "SERIALIZABLE_SYM", "SESSION_SYM", "SHUTDOWN", 
  "SSL_SYM", "STARTING", "STATUS_SYM", "STRAIGHT_JOIN", "SUBJECT_SYM", 
  "TABLES", "TABLE_SYM", "TEMPORARY", "TERMINATED", "TEXT_STRING", 
  "TO_SYM", "TRAILING", "TRANSACTION_SYM", "TYPE_SYM", "FUNC_ARG0", 
  "FUNC_ARG1", "FUNC_ARG2", "FUNC_ARG3", "UDF_RETURNS_SYM", 
  "UDF_SONAME_SYM", "UDF_SYM", "UNCOMMITTED_SYM", "UNION_SYM", 
  "UNIQUE_SYM", "USAGE", "USE_FRM", "USE_SYM", "USING", "VALUES", 
  "VARIABLES", "WHERE", "WITH", "WRITE_SYM", "X509_SYM", "XOR", 
  "COMPRESSED_SYM", "BIGINT", "BLOB_SYM", "CHAR_SYM", "CHANGED", 
  "COALESCE", "DATETIME", "DATE_SYM", "DECIMAL_SYM", "DOUBLE_SYM", "ENUM", 
  "FAST_SYM", "FLOAT_SYM", "INT_SYM", "LIMIT", "LONGBLOB", "LONGTEXT", 
  "MEDIUMBLOB", "MEDIUMINT", "MEDIUMTEXT", "NUMERIC_SYM", "PRECISION", 
  "QUICK", "REAL", "SIGNED_SYM", "SMALLINT", "STRING_SYM", "TEXT_SYM", 
  "TIMESTAMP", "TIME_SYM", "TINYBLOB", "TINYINT", "TINYTEXT", 
  "ULONGLONG_NUM", "UNSIGNED", "VARBINARY", "VARCHAR", "VARYING", 
  "ZEROFILL", "AGAINST", "ATAN", "BETWEEN_SYM", "BIT_AND", "BIT_OR", 
  "CASE_SYM", "CONCAT", "CONCAT_WS", "CURDATE", "CURTIME", "DATABASE", 
  "DATE_ADD_INTERVAL", "DATE_SUB_INTERVAL", "DAY_HOUR_SYM", 
  "DAY_MINUTE_SYM", "DAY_SECOND_SYM", "DAY_SYM", "DECODE_SYM", 
  "DES_ENCRYPT_SYM", "DES_DECRYPT_SYM", "ELSE", "ELT_FUNC", "ENCODE_SYM", 
  "ENCRYPT", "EXPORT_SET", "EXTRACT_SYM", "FIELD_FUNC", "FORMAT_SYM", 
  "FOR_SYM", "FROM_UNIXTIME", "GROUP_UNIQUE_USERS", "HOUR_MINUTE_SYM", 
  "HOUR_SECOND_SYM", "HOUR_SYM", "IDENTIFIED_SYM", "IF", "INSERT_METHOD", 
  "INTERVAL_SYM", "LAST_INSERT_ID", "LEFT", "LOCATE", "MAKE_SET_SYM", 
  "MASTER_POS_WAIT", "MINUTE_SECOND_SYM", "MINUTE_SYM", "MODE_SYM", 
  "MODIFY_SYM", "MONTH_SYM", "NOW_SYM", "PASSWORD", "POSITION_SYM", 
  "PROCEDURE", "RAND", "REPLACE", "RIGHT", "ROUND", "SECOND_SYM", 
  "SHARE_SYM", "SUBSTRING", "SUBSTRING_INDEX", "TRIM", "UDA_CHAR_SUM", 
  "UDA_FLOAT_SUM", "UDA_INT_SUM", "UDF_CHAR_FUNC", "UDF_FLOAT_FUNC", 
  "UDF_INT_FUNC", "UNIQUE_USERS", "UNIX_TIMESTAMP", "USER", "WEEK_SYM", 
  "WHEN_SYM", "WORK_SYM", "YEAR_MONTH_SYM", "YEAR_SYM", "YEARWEEK", 
  "BENCHMARK_SYM", "END", "THEN_SYM", "SQL_BIG_RESULT", "SQL_CACHE_SYM", 
  "SQL_CALC_FOUND_ROWS", "SQL_NO_CACHE_SYM", "SQL_SMALL_RESULT", 
  "SQL_BUFFER_RESULT", "ISSUER_SYM", "CIPHER_SYM", "'|'", "'&'", "'-'", 
  "'+'", "'*'", "'/'", "'%'", "'~'", "NEG", "'^'", "'('", "')'", "','", 
  "'!'", "'{'", "'}'", "'@'", "'.'", "$accept", "query", "verb_clause", 
  "change", "@1", "master_defs", "master_def", "create", "@2", "@3", "@4", 
  "create2", "create2a", "@5", "create3", "@6", "@7", "create_select", 
  "@8", "opt_as", "opt_table_options", "table_options", "table_option", 
  "opt_if_not_exists", "opt_create_table_options", "create_table_options", 
  "create_table_option", "table_types", "row_types", "raid_types", 
  "merge_insert_types", "opt_select_from", "udf_func_type", "udf_type", 
  "field_list", "field_list_item", "column_def", "key_def", 
  "check_constraint", "opt_constraint", "field_spec", "@9", "type", "@10", 
  "@11", "char", "varchar", "int_type", "real_type", "float_options", 
  "precision", "field_options", "field_opt_list", "field_option", 
  "opt_len", "opt_precision", "opt_attribute", "opt_attribute_list", 
  "attribute", "opt_binary", "references", "opt_on_delete", 
  "opt_on_delete_list", "opt_on_delete_item", "delete_option", "key_type", 
  "key_or_index", "keys_or_index", "opt_unique_or_fulltext", "key_list", 
  "key_part", "opt_ident", "string_list", "alter", "@12", "alter_list", 
  "add_column", "alter_list_item", "@13", "@14", "@15", "opt_column", 
  "opt_ignore", "opt_restrict", "opt_place", "opt_to", "slave", "start", 
  "@16", "slave_thread_opts", "slave_thread_opt", "restore", "@17", 
  "backup", "@18", "repair", "@19", "opt_mi_repair_type", 
  "mi_repair_types", "mi_repair_type", "analyze", "@20", "check", "@21", 
  "opt_mi_check_type", "mi_check_types", "mi_check_type", "optimize", 
  "@22", "rename", "@23", "table_to_table_list", "table_to_table", 
  "select", "select_init", "@24", "@25", "select_part2", "@26", 
  "select_into", "select_from", "select_options", "select_option_list", 
  "select_option", "select_lock_type", "select_item_list", "select_item", 
  "remember_name", "remember_end", "select_item2", "select_alias", 
  "optional_braces", "expr", "expr_expr", "no_in_expr", "no_and_expr", 
  "simple_expr", "udf_expr_list", "sum_expr", "@27", "@28", "in_sum_expr", 
  "@29", "cast_type", "expr_list", "@30", "expr_list2", "ident_list_arg", 
  "ident_list", "@31", "ident_list2", "opt_expr", "opt_else", "when_list", 
  "@32", "when_list2", "opt_pad", "join_table_list", "@33", "@34", "@35", 
  "normal_join", "join_table", "@36", "opt_outer", "opt_key_definition", 
  "key_usage_list", "@37", "key_usage_list2", "using_list", "interval", 
  "table_alias", "opt_table_alias", "opt_all", "where_clause", 
  "having_clause", "@38", "opt_escape", "group_clause", "group_list", 
  "olap_opt", "opt_order_clause", "order_clause", "@39", "order_list", 
  "order_dir", "limit_clause", "@40", "limit_options", 
  "delete_limit_clause", "ULONG_NUM", "ulonglong_num", "procedure_clause", 
  "@41", "procedure_list", "procedure_list2", "procedure_item", 
  "opt_into", "@42", "do", "@43", "drop", "@44", "table_list", 
  "table_name", "if_exists", "opt_temporary", "insert", "@45", "@46", 
  "replace", "@47", "@48", "insert_lock_option", "replace_lock_option", 
  "insert2", "insert_table", "insert_field_spec", "@49", "opt_field_spec", 
  "fields", "insert_values", "@50", "@51", "values_list", "ident_eq_list", 
  "ident_eq_value", "equal", "opt_equal", "no_braces", "@52", 
  "opt_values", "values", "expr_or_default", "update", "@53", 
  "update_list", "opt_low_priority", "delete", "@54", "single_multi", 
  "@55", "@56", "@57", "table_wild_list", "table_wild_one", "opt_wild", 
  "opt_delete_options", "opt_delete_option", "truncate", "opt_table_sym", 
  "show", "@58", "show_param", "@59", "opt_db", "wild", "opt_full", 
  "from_or_in", "binlog_in", "binlog_from", "describe", "@60", 
  "describe_command", "opt_describe_column", "flush", "@61", 
  "flush_options", "flush_option", "@62", "opt_table_list", "reset", 
  "@63", "reset_options", "reset_option", "purge", "@64", "kill", "use", 
  "load", "@65", "opt_local", "load_data_lock", "opt_duplicate", 
  "opt_field_term", "field_term_list", "field_term", "opt_line_term", 
  "line_term_list", "line_term", "opt_ignore_lines", "text_literal", 
  "text_string", "literal", "insert_ident", "table_wild", "order_ident", 
  "simple_ident", "field_ident", "table_ident", "ident", "ident_or_text", 
  "user", "keyword", "set", "@66", "opt_option", "option_value_list", 
  "option_type", "opt_var_type", "opt_var_ident_type", "option_value", 
  "internal_variable_name", "isolation_types", "text_or_password", 
  "set_expr_or_default", "lock", "@67", "table_or_tables", 
  "table_lock_list", "table_lock", "lock_option", "unlock", "handler", 
  "@68", "handler_read_or_scan", "handler_scan_function", 
  "handler_rkey_function", "@69", "handler_rkey_mode", "revoke", "@70", 
  "grant", "@71", "grant_privileges", "grant_privilege_list", 
  "grant_privilege", "@72", "@73", "@74", "@75", "opt_and", 
  "require_list", "require_list_element", "opt_table", "user_list", 
  "grant_user", "opt_column_list", "column_list", "column_list_id", 
  "require_clause", "grant_options", "grant_option_list", "grant_option", 
  "begin", "@76", "opt_work", "commit", "rollback", "savepoint", 
  "opt_union", "union_list", "@77", "union_opt", 
  "optional_order_or_limit", "@78", "union_option", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395,   396,   397,   398,   399,   400,   401,   402,   403,   404,
     405,   406,   407,   408,   409,   410,   411,   412,   413,   414,
     415,   416,   417,   418,   419,   420,   421,   422,   423,   424,
     425,   426,   427,   428,   429,   430,   431,   432,   433,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   464,
     465,   466,   467,   468,   469,   470,   471,   472,   473,   474,
     475,   476,   477,   478,   479,   480,   481,   482,   483,   484,
     485,   486,   487,   488,   489,   490,   491,   492,   493,   494,
     495,   496,   497,   498,   499,   500,   501,   502,   503,   504,
     505,   506,   507,   508,   509,   510,   511,   512,   513,   514,
     515,   516,   517,   518,   519,   520,   521,   522,   523,   524,
     525,   526,   527,   528,   529,   530,   531,   532,   533,   534,
     535,   536,   537,   538,   539,   540,   541,   542,   543,   544,
     545,   546,   547,   548,   549,   550,   551,   552,   553,   554,
     555,   556,   557,   558,   559,   560,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,   571,   572,   573,   574,
     575,   576,   577,   578,   579,   580,   581,   582,   583,   584,
     585,   586,   587,   588,   589,   590,   591,   592,   593,   594,
     595,   596,   597,   598,   599,   600,   601,   602,   603,   604,
     605,   606,   607,   608,   609,   610,   611,   612,   613,   614,
     615,   616,   617,   618,   619,   620,   621,   622,   623,   624,
     625,   626,   627,   628,   629,   630,   631,   632,   633,   634,
     635,   636,   637,   638,   639,   640,   641,   642,   643,   644,
     645,   646,   647,   648,   124,    38,    45,    43,    42,    47,
      37,   126,   649,    94,    40,    41,    44,    33,   123,   125,
      64,    46
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned short yyr1[] =
{
       0,   412,   413,   413,   414,   414,   414,   414,   414,   414,
     414,   414,   414,   414,   414,   414,   414,   414,   414,   414,
     414,   414,   414,   414,   414,   414,   414,   414,   414,   414,
     414,   414,   414,   414,   414,   414,   414,   414,   414,   414,
     414,   414,   416,   415,   417,   417,   418,   418,   418,   418,
     418,   418,   418,   418,   418,   420,   419,   421,   419,   419,
     422,   419,   423,   423,   424,   425,   424,   426,   427,   426,
     428,   426,   430,   429,   431,   431,   432,   432,   433,   433,
     434,   435,   435,   436,   436,   437,   437,   438,   438,   438,
     438,   438,   438,   438,   438,   438,   438,   438,   438,   438,
     438,   438,   438,   438,   438,   438,   438,   438,   439,   439,
     439,   439,   439,   439,   439,   440,   440,   440,   440,   441,
     441,   441,   442,   442,   442,   443,   443,   444,   444,   445,
     445,   445,   446,   446,   447,   447,   448,   448,   449,   449,
     449,   450,   450,   451,   451,   453,   452,   454,   454,   454,
     454,   454,   454,   454,   454,   454,   454,   454,   454,   454,
     454,   454,   454,   454,   454,   454,   454,   454,   454,   454,
     454,   454,   454,   454,   454,   455,   454,   456,   454,   457,
     457,   457,   458,   458,   458,   458,   459,   459,   459,   459,
     459,   460,   460,   460,   461,   461,   461,   462,   463,   463,
     464,   464,   465,   465,   465,   466,   466,   467,   467,   468,
     468,   469,   469,   470,   470,   470,   470,   470,   470,   470,
     470,   471,   471,   471,   472,   472,   473,   473,   474,   474,
     475,   475,   475,   475,   476,   476,   476,   476,   476,   477,
     477,   477,   477,   477,   477,   478,   478,   479,   479,   479,
     480,   480,   480,   481,   481,   482,   482,   483,   483,   484,
     484,   486,   485,   487,   487,   487,   488,   489,   489,   489,
     490,   489,   491,   492,   489,   489,   489,   489,   489,   489,
     489,   489,   489,   489,   489,   489,   493,   493,   494,   494,
     495,   495,   495,   496,   496,   496,   497,   497,   497,   497,
     498,   498,   498,   498,   500,   499,   501,   501,   502,   502,
     502,   504,   503,   506,   505,   508,   507,   509,   509,   510,
     510,   511,   511,   511,   513,   512,   515,   514,   516,   516,
     517,   517,   518,   518,   518,   518,   518,   520,   519,   522,
     521,   523,   523,   524,   525,   527,   526,   528,   526,   530,
     529,   531,   531,   531,   531,   532,   533,   533,   534,   534,
     535,   535,   535,   535,   535,   535,   535,   535,   535,   535,
     536,   536,   536,   537,   537,   537,   538,   539,   540,   541,
     541,   542,   542,   542,   542,   542,   543,   543,   544,   544,
     545,   545,   545,   545,   545,   545,   545,   545,   545,   545,
     545,   545,   545,   545,   545,   545,   545,   545,   545,   545,
     545,   545,   545,   545,   545,   545,   545,   545,   545,   545,
     545,   545,   545,   546,   546,   546,   546,   546,   546,   546,
     546,   546,   546,   546,   546,   546,   546,   546,   546,   546,
     546,   546,   546,   546,   546,   546,   546,   546,   546,   546,
     546,   546,   546,   546,   546,   547,   547,   547,   547,   547,
     547,   547,   547,   547,   547,   547,   547,   547,   547,   547,
     547,   547,   547,   547,   547,   547,   547,   547,   547,   547,
     547,   547,   547,   547,   547,   547,   547,   547,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   548,   549,   549,   550,   550,
     550,   550,   550,   551,   552,   550,   550,   550,   550,   550,
     550,   554,   553,   555,   555,   555,   555,   555,   555,   555,
     555,   555,   557,   556,   558,   558,   559,   559,   561,   560,
     562,   562,   563,   563,   564,   564,   566,   565,   567,   567,
     568,   568,   569,   569,   569,   569,   569,   569,   570,   569,
     569,   571,   569,   569,   569,   572,   569,   569,   569,   573,
     573,   573,   575,   574,   574,   576,   576,   577,   577,   577,
     577,   579,   578,   580,   580,   580,   581,   581,   582,   582,
     582,   582,   582,   582,   582,   582,   582,   582,   582,   582,
     582,   583,   583,   583,   584,   584,   585,   585,   586,   586,
     587,   588,   587,   589,   589,   590,   590,   591,   591,   592,
     592,   592,   593,   593,   595,   594,   596,   596,   597,   597,
     597,   598,   599,   598,   600,   600,   600,   601,   601,   602,
     602,   602,   602,   602,   603,   603,   603,   603,   603,   604,
     605,   604,   606,   606,   607,   607,   608,   610,   609,   609,
     612,   611,   613,   614,   613,   613,   613,   615,   615,   616,
     617,   617,   618,   618,   620,   621,   619,   623,   624,   622,
     625,   625,   625,   625,   626,   626,   627,   627,   628,   629,
     629,   629,   630,   629,   631,   631,   631,   632,   632,   633,
     634,   633,   635,   633,   636,   636,   637,   637,   638,   639,
     639,   640,   640,   642,   641,   643,   643,   644,   644,   645,
     645,   647,   646,   648,   648,   649,   649,   651,   650,   653,
     652,   654,   652,   655,   652,   656,   656,   657,   657,   658,
     658,   659,   659,   660,   660,   661,   662,   662,   664,   663,
     665,   665,   665,   665,   665,   665,   665,   665,   666,   665,
     665,   665,   665,   665,   665,   665,   665,   665,   665,   665,
     667,   667,   668,   668,   669,   669,   670,   670,   671,   671,
     672,   672,   674,   673,   673,   675,   675,   676,   676,   676,
     678,   677,   679,   679,   681,   680,   680,   680,   680,   680,
     680,   680,   680,   680,   680,   680,   682,   682,   684,   683,
     685,   685,   686,   686,   686,   688,   687,   689,   690,   692,
     691,   691,   691,   693,   693,   694,   694,   694,   695,   695,
     695,   696,   696,   697,   697,   698,   698,   698,   698,   699,
     699,   700,   700,   701,   701,   702,   702,   703,   703,   704,
     704,   705,   705,   705,   705,   705,   705,   705,   705,   705,
     705,   705,   706,   706,   707,   707,   708,   709,   709,   709,
     709,   710,   710,   710,   711,   711,   711,   712,   712,   713,
     713,   713,   714,   714,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   715,   715,   715,   715,   715,   715,   715,   715,   715,
     715,   717,   716,   718,   718,   719,   719,   720,   720,   720,
     720,   721,   721,   721,   721,   722,   722,   722,   722,   723,
     723,   723,   723,   723,   723,   723,   724,   725,   725,   725,
     725,   726,   726,   727,   727,   727,   727,   729,   728,   730,
     730,   731,   731,   732,   733,   733,   733,   733,   734,   735,
     735,   736,   735,   737,   737,   738,   738,   739,   739,   739,
     739,   740,   739,   741,   741,   741,   741,   741,   743,   742,
     745,   744,   746,   746,   746,   747,   747,   749,   748,   750,
     748,   751,   748,   752,   748,   748,   748,   748,   748,   748,
     748,   748,   748,   748,   748,   748,   748,   748,   748,   748,
     748,   748,   748,   753,   753,   754,   754,   755,   755,   755,
     756,   756,   756,   756,   757,   757,   758,   758,   758,   759,
     759,   760,   760,   761,   762,   762,   762,   762,   762,   763,
     763,   764,   764,   765,   765,   765,   765,   767,   766,   768,
     768,   769,   770,   770,   771,   772,   772,   774,   773,   775,
     775,   776,   777,   776,   778,   778
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     1,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     0,     5,     1,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     0,     7,     0,    10,     4,
       0,     9,     2,     2,     4,     0,     4,     0,     0,     5,
       0,     7,     0,     5,     0,     1,     0,     1,     1,     2,
       1,     0,     3,     0,     1,     1,     2,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     5,     3,     4,     3,     4,     4,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     0,     2,     0,     1,     1,
       1,     1,     1,     3,     1,     1,     2,     2,     5,     8,
       2,     0,     2,     0,     2,     0,     4,     3,     3,     3,
       2,     1,     5,     2,     4,     5,     4,     3,     1,     1,
       1,     4,     1,     1,     1,     1,     1,     2,     2,     1,
       1,     1,     1,     3,     3,     0,     5,     0,     5,     1,
       1,     2,     2,     1,     2,     2,     1,     1,     1,     1,
       1,     1,     1,     2,     0,     3,     1,     5,     0,     1,
       2,     1,     1,     1,     1,     0,     3,     0,     1,     0,
       1,     2,     1,     1,     2,     2,     1,     2,     1,     2,
       2,     0,     1,     4,     3,     6,     0,     1,     2,     1,
       3,     3,     2,     2,     1,     1,     2,     2,     2,     3,
       1,     1,     2,     2,     3,     1,     1,     1,     1,     1,
       0,     1,     1,     4,     2,     1,     4,     0,     1,     1,
       3,     0,     6,     0,     1,     3,     2,     3,     2,     4,
       0,     6,     0,     0,     8,     4,     3,     4,     3,     2,
       2,     6,     5,     3,     1,     1,     0,     1,     0,     1,
       0,     1,     1,     0,     2,     1,     0,     1,     1,     1,
       3,     3,     3,     3,     0,     3,     1,     3,     0,     1,
       1,     0,     6,     0,     6,     0,     5,     0,     1,     1,
       2,     1,     1,     1,     0,     5,     0,     5,     0,     1,
       1,     2,     1,     1,     1,     1,     1,     0,     5,     0,
       4,     1,     3,     3,     1,     0,     4,     0,     6,     0,
       5,     1,     1,     2,     2,     8,     0,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       0,     2,     4,     3,     1,     1,     4,     0,     0,     1,
       1,     0,     2,     2,     1,     1,     0,     2,     1,     1,
       5,     6,     5,     6,     3,     3,     3,     3,     4,     5,
       3,     4,     3,     4,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     5,     5,     5,     6,     3,     3,     3,     3,     4,
       5,     3,     4,     3,     4,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     5,     5,     1,     5,     6,     5,     6,     3,
       3,     3,     4,     5,     3,     4,     3,     4,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     5,     5,     1,     1,     1,
       4,     2,     4,     1,     2,     2,     2,     2,     3,     4,
       6,     9,     2,     6,     6,     6,     3,     4,     6,     8,
       4,     6,     4,     4,     4,     6,     2,     2,     4,     8,
       8,     3,     6,     6,     4,     6,     6,     6,     4,     6,
       4,     6,     8,    10,    12,     6,     4,     6,     6,     4,
       8,    10,     5,     6,     3,     4,     6,     6,     8,     6,
       6,     4,     6,     6,     8,     4,     4,     2,     4,     4,
       6,     4,     3,     8,     6,     4,     6,     4,     8,     6,
       8,     6,     8,     4,     7,     7,     7,     6,     6,     4,
       4,     4,     4,     4,     4,    10,     3,     4,     3,     4,
       6,     4,     4,     6,     6,     6,     0,     1,     4,     4,
       4,     5,     4,     0,     0,     7,    10,     4,     4,     4,
       4,     0,     3,     1,     1,     1,     2,     1,     2,     1,
       1,     1,     0,     2,     1,     3,     1,     3,     0,     2,
       1,     3,     0,     1,     0,     2,     0,     2,     3,     5,
       0,     1,     3,     1,     3,     3,     3,     5,     0,     8,
       7,     0,    10,     6,     7,     0,    10,     6,     4,     1,
       2,     2,     0,     4,    10,     0,     1,     0,     2,     2,
       2,     0,     5,     3,     1,     1,     1,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     0,     1,     1,     0,     2,     0,     1,     0,     2,
       0,     0,     3,     2,     0,     0,     4,     4,     2,     0,
       2,     2,     0,     1,     0,     4,     4,     2,     0,     1,
       1,     0,     0,     3,     1,     3,     3,     0,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     0,
       0,     6,     0,     1,     3,     1,     2,     0,     6,     3,
       0,     3,     6,     0,     6,     4,     3,     1,     3,     1,
       0,     2,     0,     1,     0,     0,     7,     0,     0,     6,
       0,     1,     1,     1,     1,     1,     2,     1,     1,     1,
       3,     4,     0,     3,     0,     3,     2,     3,     1,     2,
       0,     3,     0,     5,     3,     1,     3,     1,     3,     1,
       1,     0,     1,     0,     4,     0,     1,     3,     1,     1,
       1,     0,    10,     5,     3,     0,     1,     0,     4,     0,
       6,     0,     5,     0,     6,     1,     3,     2,     4,     0,
       2,     0,     2,     1,     1,     3,     0,     1,     0,     3,
       2,     3,     4,     4,     6,    16,     2,     2,     0,     6,
       4,     2,     2,     2,     3,     1,     3,     3,     2,     2,
       0,     2,     0,     2,     0,     1,     1,     1,     0,     2,
       0,     2,     0,     4,     2,     1,     1,     0,     1,     1,
       0,     3,     3,     1,     0,     3,     4,     2,     1,     1,
       1,     1,     1,     1,     1,     1,     0,     1,     0,     3,
       3,     1,     1,     1,     2,     0,     6,     2,     2,     0,
      15,     5,     4,     0,     1,     0,     1,     1,     0,     1,
       1,     0,     2,     2,     1,     3,     4,     3,     3,     0,
       2,     2,     1,     3,     3,     0,     3,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     2,
       2,     2,     1,     1,     3,     5,     1,     1,     3,     4,
       5,     1,     3,     2,     1,     3,     2,     1,     1,     1,
       1,     1,     1,     3,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     0,     4,     0,     1,     2,     4,     0,     1,     1,
       1,     0,     1,     1,     1,     0,     2,     2,     2,     4,
       3,     6,     4,     4,     3,     5,     1,     2,     2,     2,
       1,     1,     4,     1,     1,     1,     1,     0,     4,     1,
       1,     1,     3,     3,     1,     1,     2,     2,     2,     4,
       3,     0,     7,     1,     2,     1,     1,     1,     1,     1,
       1,     0,     5,     1,     1,     1,     1,     1,     0,     7,
       0,     9,     1,     2,     1,     1,     3,     0,     3,     0,
       3,     0,     3,     0,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     2,     2,     1,     3,
       2,     2,     2,     0,     1,     3,     1,     2,     2,     2,
       1,     3,     3,     1,     1,     3,     4,     5,     1,     0,
       3,     3,     1,     1,     0,     2,     2,     2,     2,     0,
       2,     2,     1,     2,     2,     2,     2,     0,     3,     0,
       1,     1,     1,     4,     2,     0,     1,     0,     4,     1,
       1,     0,     0,     3,     0,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned short yydefact[] =
{
       0,     2,     0,   288,     0,  1267,     0,  1271,    76,   817,
     750,   762,   880,   764,     0,     0,     0,     0,   905,     0,
     898,  1272,     0,   349,   838,     0,     0,     0,   836,     0,
     811,     0,     0,   875,   876,  1200,     0,     0,  1198,  1133,
       0,   767,     0,     0,     0,     8,    11,     4,    34,    35,
      28,     6,    25,     5,     9,    22,    24,    32,   344,    14,
      15,    17,    26,    40,    12,    37,    36,    13,     0,    18,
      27,    23,    21,    41,    19,    33,    20,    39,    38,    29,
      16,     7,    10,    30,    31,   994,  1028,  1039,  1067,  1075,
     975,   980,   982,   984,   993,   995,   997,  1000,  1008,  1014,
    1015,  1024,  1038,  1042,  1045,  1070,  1088,  1090,  1091,  1094,
    1095,  1099,  1106,  1110,  1111,  1113,  1116,  1120,   974,   977,
     978,   979,   981,   983,   985,   986,   987,   988,   990,   991,
     996,   999,  1001,  1005,  1006,  1018,  1010,  1019,  1007,  1013,
    1016,  1021,  1022,  1023,  1020,  1026,  1025,  1027,  1029,   967,
    1032,  1036,  1033,  1034,  1040,  1041,  1043,  1046,  1050,  1048,
    1049,  1051,  1047,  1052,  1085,  1086,  1044,  1053,  1054,  1055,
    1056,  1057,  1058,  1060,  1064,  1065,  1068,  1066,  1069,  1071,
    1072,  1009,  1073,  1076,  1077,  1078,  1080,  1083,  1084,  1081,
    1082,  1087,  1089,  1092,  1093,  1096,  1097,  1098,  1101,  1102,
    1105,  1112,  1115,  1117,  1119,  1123,  1124,  1125,  1126,  1127,
    1129,   998,   989,  1002,  1003,  1012,  1017,  1079,  1103,  1114,
    1118,  1121,  1122,   976,  1004,  1030,  1031,  1037,  1059,  1062,
    1061,  1063,  1074,  1100,  1104,  1128,  1130,  1011,  1107,  1109,
    1108,  1035,   992,     0,     0,   964,   968,   289,     0,  1170,
    1169,   324,  1269,     0,   128,   252,    80,   251,    81,     0,
      77,    78,     0,     0,   831,     0,     0,   763,     0,   760,
       0,     0,   770,   980,     0,     0,     0,     0,     0,     0,
    1120,     0,     0,     0,   946,     0,   948,     0,     0,   943,
     628,     0,   947,   942,   945,   937,     0,     0,     0,     0,
       0,     0,  1003,  1121,  1122,   944,     0,     0,     0,   632,
       0,     0,   386,   386,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  1030,
       0,     0,     0,     0,     0,     0,     0,  1059,  1063,   386,
    1074,     0,     0,     0,     0,     0,  1100,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    1130,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     907,   388,   389,   493,   941,   489,   488,   957,   915,     0,
    1167,   337,     0,   315,     0,     0,  1274,   345,   356,   864,
     308,   308,   308,   304,   308,   837,     0,  1178,   815,   313,
     326,     0,   339,   311,     0,  1134,  1131,   908,   815,   349,
       1,     3,   874,   872,   966,  1180,   691,  1181,     0,     0,
       0,  1270,  1268,    42,     0,     0,    81,    79,     0,     0,
     834,   833,     0,   831,   810,   809,   751,   808,     0,   756,
       0,     0,   760,   893,   892,   894,   888,   890,   889,     0,
     895,   891,  1170,   881,   883,   884,   772,   773,   771,   288,
     696,   696,     0,   696,   696,   696,   696,     0,   502,     0,
       0,     0,     0,     0,   628,     0,   626,     0,   496,     0,
       0,     0,     0,   622,   622,   949,   951,   950,     0,   696,
     696,   633,     0,   622,     0,     0,   516,     0,   517,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   557,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   622,   622,   622,
     622,   622,   622,     0,     0,     0,     0,     0,     0,     0,
     494,   495,     0,   497,     0,   971,   970,  1145,   969,   491,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   938,     0,
     916,     0,   917,   913,     0,     0,     0,     0,     0,   903,
     902,     0,   899,   901,     0,  1275,   369,   362,   361,   360,
     364,   368,   366,   367,   363,   365,   377,   357,   359,     0,
       0,     0,     0,   862,   865,  1144,     0,   248,   249,     0,
     247,  1142,   855,     0,     0,  1143,   862,   860,     0,     0,
     839,     0,     0,   310,   309,   302,   306,   303,   300,   305,
     301,   835,   759,   816,   288,     0,     0,  1218,  1219,  1215,
    1220,  1221,  1209,     0,     0,  1207,     0,  1228,  1211,  1204,
    1225,     0,  1217,  1224,  1213,  1222,  1223,  1216,     0,  1202,
    1205,     0,     0,     0,  1137,   775,     0,   774,     0,   877,
     693,   692,     0,  1179,     0,   965,   261,   328,   757,     0,
       0,    59,     0,    60,     0,     0,   818,   821,   825,   829,
     832,     0,     0,   761,   755,     0,   887,     0,     0,   896,
       0,   697,     0,   611,   603,     0,   611,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     629,   630,   506,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   636,     0,     0,   387,     0,   521,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   678,   679,   680,
     681,   682,   683,   684,   685,   686,   687,   688,   689,   690,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   544,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     454,   562,     0,     0,     0,     0,     0,     0,     0,   640,
     640,   640,     0,     0,   597,     0,     0,     0,     0,     0,
       0,   586,     0,   588,     0,     0,     0,   733,   730,   729,
     732,   731,     0,   498,     0,     0,     0,     0,     0,     0,
       0,   404,   405,   406,   407,   408,   409,   410,     0,   402,
     411,   412,   397,   622,   704,     0,     0,     0,     0,   395,
     394,   400,   396,     0,   487,   417,   419,     0,   414,     0,
     413,   415,   416,   420,   418,   958,   912,   914,     0,     0,
     691,  1168,  1171,   328,     0,   317,   904,     0,  1273,  1284,
     346,  1276,   375,   721,   374,     0,   358,   868,     0,   846,
     858,   847,   859,     0,   840,     0,   852,     0,   860,   851,
     866,   867,   862,     0,   860,     0,     0,   853,   862,   308,
     662,     0,   328,     0,  1249,  1230,  1232,  1231,  1249,  1227,
    1249,  1203,  1226,  1249,     0,     0,   340,   341,     0,     0,
       0,  1138,  1139,  1140,  1132,     0,     0,   778,   768,   777,
     347,   940,   939,   873,   878,   879,   695,  1067,  1022,     0,
     698,  1183,   263,   335,   334,   336,   333,   332,     0,   325,
     329,   330,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    43,    44,    82,    55,     0,     0,   823,   819,   964,
       0,     0,     0,   827,   807,   753,   290,     0,   882,   897,
     885,   765,   598,     0,   622,   602,     0,     0,   608,   607,
     609,   610,     0,     0,     0,   622,   622,   551,     0,   627,
       0,     0,   507,     0,     0,   512,   624,   623,   513,   510,
       0,   599,   600,   634,     0,   514,   622,   518,     0,     0,
       0,   530,     0,   528,     0,   622,     0,   524,     0,     0,
       0,   622,     0,   536,     0,     0,   539,     0,   622,     0,
     545,     0,     0,   622,     0,   555,   556,   558,   559,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   561,     0,     0,   565,
       0,   567,     0,     0,     0,   641,     0,     0,     0,     0,
     573,   579,   580,   581,   582,   583,   584,     0,   587,   589,
       0,   591,   592,     0,     0,   499,  1148,  1146,  1147,   492,
     490,   959,   403,     0,     0,   398,   622,   704,   401,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   911,     0,     0,   338,     0,   322,   323,   321,   316,
     318,   319,   900,  1285,  1277,   662,     0,   722,   377,   370,
     352,   351,     0,   378,   380,   379,   957,     0,   870,   857,
     863,   972,   856,     0,   862,   841,   861,   862,   860,     0,
     854,   307,   662,     0,     0,   643,     0,     0,   327,  1229,
       0,  1210,  1208,  1212,  1214,  1240,  1243,   964,     0,  1206,
       0,     0,     0,     0,  1137,  1119,     0,     0,     0,  1156,
    1135,     0,   776,     0,  1282,  1190,  1188,  1189,  1193,  1194,
    1196,  1195,  1197,  1187,  1184,  1191,     0,   721,   286,   286,
     286,     0,   286,     0,     0,   801,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   296,
       0,     0,     0,     0,     0,   286,     0,   284,    85,   262,
       0,   264,   285,   758,   331,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    83,     0,    57,     0,   698,
       0,   826,   662,   830,   829,   754,   292,   291,   752,   886,
       0,   612,   604,   601,     0,     0,   613,   614,   621,   619,
     615,   620,   617,     0,     0,     0,     0,     0,     0,   631,
       0,     0,     0,     0,     0,     0,     0,   637,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   542,     0,     0,     0,     0,
     435,   436,   437,   438,   439,   440,   441,     0,   433,   442,
     443,   428,     0,   704,     0,     0,     0,   426,   425,   431,
     427,     0,   448,   450,     0,   445,     0,   444,   446,   447,
     451,   449,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   390,   703,     0,   399,
       0,   468,   469,   470,   471,   472,   473,   474,     0,   466,
     475,   476,   392,   622,   704,     0,     0,     0,     0,   460,
     459,   464,   461,     0,   481,   483,     0,   478,     0,   477,
     479,   480,   484,   482,   422,   421,   960,   909,     0,  1174,
    1175,  1173,  1172,   906,   320,     0,   698,     0,     0,     0,
     373,     0,     0,   350,   354,   353,   381,     0,   869,     0,
     848,     0,     0,   843,   842,   850,   860,     0,   662,     0,
       0,   659,     0,     0,   662,   665,   665,   662,   662,   691,
     314,  1253,     0,  1252,     0,     0,     0,   342,   343,   312,
       0,     0,     0,   801,   799,   800,     0,     0,  1145,     0,
       0,    72,   782,     0,     0,   790,   769,   779,  1279,   348,
    1280,   712,     0,   699,  1182,   287,   257,   241,   246,   245,
     268,   141,   257,   240,   266,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   802,     0,     0,     0,     0,   279,
     280,     0,     0,     0,   714,     0,     0,     0,     0,   298,
     299,   297,     0,     0,     0,     0,   801,     0,     0,     0,
      86,     0,   143,     0,   293,   141,   145,   961,    46,    47,
      49,   738,   736,   734,   737,   735,    51,    48,    50,    52,
      53,    54,    45,   143,    56,   918,    84,   131,   130,   129,
       0,     0,   662,   712,   965,   698,     0,   828,   766,     0,
       0,   578,   616,   618,   503,   505,   549,   550,   552,     0,
     500,   508,     0,   625,   511,   635,   504,     0,     0,   515,
       0,     0,   526,   531,   529,   522,   527,   525,     0,   595,
     538,   535,   537,     0,     0,   543,   546,   547,     0,   523,
     553,     0,   434,   560,   429,   704,   432,     0,     0,     0,
       0,     0,   564,   566,     0,   571,   569,     0,     0,     0,
       0,     0,   577,     0,   590,   593,   594,   391,   393,   467,
       0,   462,   622,   704,   465,     0,     0,     0,     0,   918,
    1176,  1177,  1278,   705,   747,   749,   723,   724,     0,   371,
       0,   385,   376,   384,   954,   958,   871,   721,   973,     0,
     862,   642,     0,   661,   660,   662,   665,   665,   698,     0,
     646,   666,     0,     0,   644,   645,   667,  1250,     0,  1242,
    1241,  1248,  1254,  1244,  1199,  1136,     0,     0,     0,  1161,
       0,  1154,     0,     0,  1166,  1164,  1165,  1163,  1150,   356,
       0,   803,   789,   795,     0,     0,     0,   788,   953,   952,
    1275,   721,   713,     0,   144,   258,   242,     0,     0,     0,
     243,   140,     0,     0,   270,    92,   257,   276,   278,   290,
      93,    90,   103,    96,     0,    97,     0,    88,    89,     0,
      95,    94,   120,   119,    99,   121,   100,   101,   283,   115,
     117,   116,   118,    98,   113,   111,   114,   108,   110,   112,
     109,    87,     0,     0,   124,   123,   122,   105,   272,    91,
     265,     0,   132,   134,   135,   963,     0,   295,   267,     0,
     136,   137,     0,     0,    62,     0,     0,   920,   919,    63,
      74,     0,     0,   698,   727,   822,   605,     0,     0,     0,
     638,     0,     0,     0,     0,     0,     0,     0,     0,   430,
       0,   423,   453,   452,     0,     0,     0,     0,   576,   574,
     575,     0,   455,     0,   463,     0,   457,   486,   485,     0,
       0,   700,   921,     0,     0,     0,   383,   382,     0,   849,
       0,   844,     0,   658,     0,     0,     0,   712,     0,   662,
     662,     0,   648,     0,     0,     0,   663,  1251,     0,     0,
       0,  1259,     0,     0,  1160,  1152,  1153,     0,     0,     0,
    1149,   377,   783,   797,     0,   805,     0,     0,   780,   792,
       0,     0,   791,  1283,     0,   142,   257,   239,   244,     0,
       0,     0,     0,   277,   275,   106,   107,   956,   715,   718,
       0,   104,     0,   269,   143,   294,   226,     0,   205,   151,
       0,     0,   180,   177,   190,   164,   179,   162,   158,   194,
     192,   175,   194,   186,   166,   172,   165,   189,   171,   194,
     191,   188,   170,   160,   159,   163,   187,   169,     0,   183,
     205,   209,   221,     0,   205,   207,   962,    65,    83,    75,
       0,    61,     0,   718,   255,   824,     0,   820,     0,     0,
     509,     0,   519,   520,   532,     0,   696,   540,   548,   554,
     424,   563,   570,   568,   572,   622,   456,   458,     0,     0,
     701,   712,     0,   929,   726,   725,   372,   955,     0,     0,
     662,   662,     0,   727,   814,   651,   655,   647,     0,   671,
     669,   670,   668,     0,  1258,  1256,     0,  1257,     0,     0,
    1255,  1233,  1245,     0,  1201,  1158,  1157,  1159,  1155,     0,
       0,   125,     0,     0,     0,   806,   794,  1282,   781,   787,
    1192,     0,     0,   282,     0,   293,     0,   719,   720,   717,
     102,   209,   133,     0,     0,     0,   224,   227,   229,     0,
       0,   150,   167,     0,   168,   181,   184,   185,     0,     0,
     198,   196,   193,     0,   198,   198,     0,     0,   198,     0,
     216,     0,     0,   213,     0,   218,   146,   210,   212,   222,
       0,   182,     0,   153,     0,   198,     0,   208,   198,  1282,
     918,     0,    68,    58,     0,   254,     0,   728,     0,   501,
     639,     0,     0,     0,     0,   709,   718,     0,   721,     0,
       0,     0,     0,   922,   924,     0,   748,     0,   662,   653,
     657,     0,   812,     0,     0,     0,     0,     0,     0,  1246,
       0,  1237,  1238,  1239,  1234,     0,     0,     0,     0,     0,
    1260,  1262,  1162,  1151,    73,   370,   796,   798,   804,   793,
       0,   138,     0,     0,     0,   281,   271,   718,   273,   232,
     233,     0,     0,     0,   228,     0,     0,     0,     0,   202,
     203,   204,   173,   199,   201,     0,   149,   174,     0,     0,
     157,   220,   215,   214,   217,   219,   211,   801,     0,     0,
     147,     0,   148,    66,    64,     0,  1275,   718,     0,   541,
     533,     0,   606,   585,   921,     0,     0,   706,   708,   702,
     739,     0,     0,     0,     0,   923,     0,     0,   930,   932,
       0,     0,   813,   650,     0,   654,     0,     0,   676,     0,
    1247,  1235,  1263,  1266,  1264,  1265,  1261,   126,     0,   716,
     293,   235,     0,   234,     0,   230,   231,   226,   154,   206,
       0,   259,   195,     0,   200,     0,   161,   156,     0,   221,
     221,    70,    69,   253,   256,     0,   929,   710,   711,   718,
       0,   355,   927,   928,     0,   925,     0,     0,   931,     0,
       0,     0,     0,   649,     0,   675,     0,   674,     0,   274,
     237,   238,   236,   225,   178,     0,     0,   176,   223,   152,
     155,  1282,   534,   935,   707,   740,   926,   934,   933,     0,
       0,     0,     0,   677,   672,     0,   139,   260,   197,    71,
       0,   784,     0,     0,   664,   652,   656,   673,     0,     0,
     910,   377,     0,   936,   786,     0,     0,     0,   743,   745,
       0,   785,   746,   741,   377,     0,   744,   845
};

/* YYDEFGOTO[NTERM-NUM]. */
static const short yydefgoto[] =
{
      -1,    43,    44,    45,   699,   981,   982,    46,  1305,  1611,
     985,  1604,  1844,  2149,  1849,  2256,  2361,  1525,  1759,  2010,
     259,   260,   261,   425,  1605,  1287,  1288,  1821,  1813,  1804,
    1827,  2204,   262,  1610,  1831,  1832,  1833,  1834,  1781,  1541,
    1585,  1842,  2001,  2123,  2118,  2002,  2003,  2004,  2005,  2120,
    2121,  2232,  2233,  2234,  2111,  2148,  2136,  2137,  2138,  2143,
    1841,  2106,  2107,  2108,  2305,  1542,  1543,   639,   263,  2012,
    2013,  1774,  2310,    47,   962,  1289,  1290,  1291,  1952,  1962,
    2300,  1544,   248,  1318,  1838,  1572,    48,    49,   649,   645,
     646,    50,   682,    51,   655,    52,   598,  1179,  1180,  1181,
      53,   420,    54,   656,   969,   970,   971,    55,   596,    56,
     681,   936,   937,    57,    58,   605,  1244,   387,   388,  1189,
    1190,   616,   617,   618,  1473,   893,   894,   895,  1476,  1193,
    1712,   496,   435,   371,   799,   863,   372,   813,   373,  1004,
    1619,   722,  1003,  1333,   814,   747,  1027,   475,   476,   477,
     740,   492,  1345,  1033,  1034,  1347,  1106,  1214,  2058,  2184,
    2186,  1498,  1215,  1216,  1732,  1916,  2060,  2188,  2346,  2287,
     780,   692,   693,   723,  1257,  2041,  2167,  1135,  1891,  2165,
    2267,  1771,  1772,  1799,  1958,  2099,  1191,  1469,  1706,  2017,
     832,  1596,  2331,  2382,  2397,  2398,  2399,  1192,  1892,    59,
     265,    60,  1315,   697,   698,   441,   270,    61,   272,  1320,
      62,   408,  1243,   459,   686,   948,   949,  1526,  1760,  2390,
    1766,  1527,  1770,  2087,  1762,  1932,  1933,  1554,  1555,  1763,
    1935,  2084,   436,   437,    63,   398,  1728,   654,    64,   264,
     706,  1309,   991,  1308,   707,   708,   993,   432,   433,    65,
     396,    66,   389,   640,  1717,   912,   904,   641,   913,  1198,
    1480,    67,   689,    68,   953,    69,   271,   453,   454,   719,
    1000,    70,   384,   602,   603,    71,   382,    72,    73,    74,
    1699,   878,   593,  1850,  2043,  2173,  2174,  2176,  2278,  2279,
    2381,   374,  2311,   375,  1767,  1768,  1959,   376,  1586,   652,
     377,  1201,  1741,   246,    75,   684,   406,   944,   945,   642,
     838,  1240,  1241,  1925,  1751,  1758,    76,   595,   455,   881,
     882,  1461,    77,    78,   694,   960,   961,  1254,  1532,  1255,
      79,   404,    80,   401,   678,   679,   680,   928,   924,   930,
     933,  2195,  2070,  2071,  1228,  1742,  1743,  1221,  1502,  1503,
    1921,  2074,  2200,  2201,    81,   252,   422,    82,    83,    84,
     890,  1528,  1465,  1529,  1530,  1531,  1184
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -2245
static const short yypact[] =
{
    1300, -2245, 11598,    23,   212, -2245,   137, -2245,   524, -2245,
   -2245,   -25, -2245, -2245,  5209,   135,   212,   212, -2245,   212,
   -2245,   -98, 24680, -2245, -2245,   578,    65,   138,   -26,   212,
   -2245,   212,   212, -2245, -2245, -2245,   212,   212, -2245,    62,
   24680, -2245,   224,   373,   435, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,  9253, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, 24680,   104,    72, -2245, -2245,   236, -2245,
   -2245, -2245,   151,   246, -2245, -2245, -2245, -2245,   241,   443,
   -2245,   417,   438,   560,   252,  3169, 24680, -2245, 24680,   366,
     472,  1328,    49,   311,   315,   327,   344,   354,   361,   374,
     381,  5209,   392,   400, -2245,   402, -2245,   424,   431, -2245,
     433,  5209, -2245, -2245, -2245, -2245,   436,   440,   442,   447,
     454,   458,   496,   496,   496, -2245,   473,   475,   488,  5209,
     493,   504,   508,   529,   533,   538,   541,   544,   554,   556,
     563,   569,   579,   583,   585,   591,   592,   594,   599,   601,
     611,  5617,   612,   618,   619,   621,   622,   623,   624,   625,
     626,   627,   629,   631,   632,   633,   638,   642,   646,   649,
     651,   652,   653,   654,   668,   673,   682,   685,   687,   691,
     692,   693,   694,  5209,  5209,  5209,  5209, 24680, 12768, 24680,
   21549, -2245, -2245, -2245,   580, -2245, -2245,   404,   379, 11598,
   -2245, -2245,   840, -2245,   132,   843, -2245, -2245,   566,  1907,
     500,   500,   500, -2245,   500, -2245, 11598, -2245,   743, -2245,
   -2245, 25437, -2245, -2245, 25437, -2245, -2245, -2245,    28, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245,   582, -2245, 24680, 11598,
   11598, -2245, -2245, -2245,   795, 24680,   241, -2245, 24680, 24680,
   -2245, -2245, 23510,   252, -2245, 21549,   595, -2245,   851, -2245,
     950, 24680,   366, -2245, -2245, -2245, -2245, -2245, -2245,  1012,
   -2245, -2245,   837,   709, -2245, -2245, -2245, -2245, -2245,    23,
    1042,    84,  5209,  1042,  1042,  1042,  1042,  5209,   -72,  5209,
    5209,  5209,  5209,  5209, -2245,   810, -2245, 11988,   -72,   713,
    5209,  5209,  5209, -2245, -2245,   580,   580,   580,  5209,  1042,
    1042, 21549,   741, -2245,  5209,   715, -2245,  3577, -2245,   717,
    5209,  5209,  5209,  5209,  5209,  5209,  5209,  5209,  5209,   920,
    5209,  5209,  5209,   496,  5209,  5209,  5209, 21358,  3985,  5209,
    5209,  5209,  5209,  5209,  5209,  3577, -2245,  5209,  5209,  4393,
    5209,  5209,  5209,  5209,  5209,  5209,  2353,   719,   719,   719,
     719,   719,   719,   496,  4801,   720,  5209,  5209,  5209,    22,
     -72,   -72, 16742,   -72,  5209, -2245, -2245,   452, -2245,  1107,
     718,  5209,  5209,  5209,  5209,  5209,  5209,  5209,   586,  5209,
    5209,  5209,   724,  5209,   290,  5209,  5209,  5209,  5209,  5209,
    5209,  5209,  6025,  6433,  5209,  5209,  5209,  5209, -2245, 24680,
   -2245,  1089, -2245,   984,  1018, 11598, 11598,   989, 11598, -2245,
   -2245,  1055,   751, -2245, 24680,   903, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245,   761,   566, -2245,  1121,
     922,   329,     4,  1007, -2245, -2245,   829, -2245, -2245,   930,
   -2245, -2245, -2245,  1118,   934, -2245,  1007,   334,   943,  1059,
   -2245,    40,   923, -2245, -2245,   778, -2245,   778,   778, -2245,
     778, -2245, -2245, -2245,    23, 11598, 11598, -2245,   946, -2245,
   -2245, -2245, -2245,   949,   143, -2245,  1088, -2245, -2245,   985,
   -2245,   995, -2245, -2245, -2245, -2245, -2245, -2245,   999,   786,
   -2245, 11598, 11598,  1001,   492, -2245, 10033, -2245,   789, 22340,
   -2245, -2245, 24680, -2245, 25070, -2245, -2245,   -21, -2245,   940,
    1079, -2245, 11598, -2245,  1004, 11598, -2245,   791, -2245,   790,
   -2245,  3169, 11598, -2245, -2245, 11598, -2245,   986,  1328, 11598,
   10033, -2245,   797, -2245, -2245,   798,   806, 14686,   800,   801,
     803,   805, 14800, 21386, 14876, 14960, 15027,  1710,   807,   809,
     811, -2245, -2245, 16795, 15108, 15151,   814,  5209,   815, 13819,
     816,   817, -2245,   818, 15274, -2245, 16890, -2245, 15298, 15372,
   15397, 13847, 13863, 15465, 15520, 13966, 15563, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
    1091, 15711, 15795, 14010,  -103, 16989, 15809, 14083,   827, -2245,
   17014, 15822, 15835, 15878, 16068, 17057, 17204, 17250, 17303, 21624,
   -2245, -2245, 17318, 16111, 16124, 14126, 17418, 14273, 16149,  5209,
    5209,  5209,  1969,   820, -2245,   828,   830,   832,   833,   834,
     -63, -2245, 17465, -2245, 14316, 17533, 14372, -2245, -2245, -2245,
   -2245, -2245,   826, -2245,  1402,   823,   836,   844, 22730,  5209,
   24680,   346,   346,   346,   346,   346,   346,   346,  1067, -2245,
     565,   565,   395, -2245,  1129,   857,  5209,  5209,  5209,   854,
     854,   346,   -78, 21813, -2245,   371,   411,  5617,   418,  5617,
     418,   -72,   -72,   -72,  1075,   852, -2245, -2245,  1123,  1217,
     110,   860, -2245,   -21,  1024,   -16, -2245,   132, -2245,  1194,
   -2245, -2245, -2245,   -37, -2245,  5209, -2245,  1124, 11598, -2245,
   -2245, -2245, -2245,    -4, -2245, 22730, -2245,   937,   334, -2245,
   -2245, -2245,  1007, 24680,   334, 11598,   334, -2245,  1007,   500,
     210,  -120,   -21,  1035,   871, -2245, -2245, -2245,   871, -2245,
     871, -2245, -2245,   871, 10423, 19773,   870, -2245,  1034,   -36,
   10423, -2245, -2245, -2245,   872, 13548, 11598, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245,    64,   121,  1168,
    1016, -2245, 25291, -2245, -2245, -2245, -2245, -2245, 11598, -2245,
   -2245,   369,  1272,  1273,  1276,  1277,  1280,  1281,  1282,  1283,
    1284,   888, -2245, -2245, -2245,  1044, 11598,   791, -2245,   -28,
   24680,  1172, 19902, -2245, -2245, -2245,     9,  1250, -2245,   892,
   -2245, -2245, -2245,  5209, -2245, -2245,   894,  5209, -2245, -2245,
   -2245, -2245,  5209,   607,   607, -2245, -2245, -2245,  5209, -2245,
    5209, 11988, -2245,  5209,  5209, -2245, 21549,   896, -2245, -2245,
    5209, -2245, -2245,   979,  5209, -2245, -2245, -2245,   963,   965,
    1069, -2245,  5209, -2245,  5209, -2245,  1070, -2245,  5209,  5209,
    5209, -2245,  1125, -2245,  5209,  1126, -2245,  5209, -2245,  5209,
   -2245,  5209,  5209, -2245,  5209, -2245, -2245, -2245, -2245,  5209,
    5209,  5209,  5209,  5209,  5209,  5209,   597,  5209,  5209,  5209,
    5209,  5209,   314,  5209,  5209,  5209,  5209,  5209,  5209,  5209,
    6841,  7249,  5209,  5209,  5209,  5209, -2245,  5209,  5209, -2245,
    5209, -2245,  5209,  5209,  5209, 21549,  1189,  1190,  1193,  5209,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245,  1128, -2245, -2245,
    5209, -2245, -2245,  5209,  5209, -2245, -2245, -2245, -2245, -2245,
   21549, -2245, -2245,   914,  1078, -2245, -2245,  1129,   346, 21838,
    5209,  5209,  5209,  5209,  5209,  5209,  5209,   616,  5209,  5209,
    5209,   917,  5209,   322,  5209,  5209,  5209,  5209,  5209,  5209,
    5209,  7657,  8065,  5209,  5209,  5209,  5209, 21358, 21358, 24680,
    1080, -2245,   234, 11598, -2245,  1083, -2245, -2245, -2245, -2245,
   -2245,   178, -2245, -2245, -2245,   210,   427, -2245, -2245,     1,
    1183, -2245,  1205, -2245, 21549, -2245,   919,  1101,  1222, -2245,
   -2245,   939, -2245,  1288,  1007, -2245, -2245,  1007,   334, 11598,
   -2245, -2245,   210, 24680,    41, -2245, 11598,  1109, -2245, -2245,
   24680, -2245, -2245, -2245, -2245,   944, -2245,   947,  1120, -2245,
   11598, 11598,  1130,  1241,   492,  1221,  1139,    97, 13158, -2245,
   -2245,   425, -2245,    -6,    82, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245,  5209,  1092,    48,  1286,
    1286,  1364,   575,  1369,  1370,   425,  1374,  1271,  1378,  1239,
    1240,  1278,  1382,  1385,  1308,  1387,  1388,  1392,  1393,    83,
    1394,  1395,  1398,  1179,  1400,  1286,  1412, -2245,  2099,  1019,
   10818, -2245, -2245, -2245, -2245,  1180,  1182,  1184,    44,  1187,
      22,    22,  1192,    22,   940,  1921,   152, -2245,  1171,  1016,
   19902, -2245,   210, -2245,  1026, -2245, -2245, -2245, -2245, -2245,
      -6, 21549, -2245, -2245, 16164, 17579, -2245, -2245, -2245, -2245,
    1159, -2245,  1160,  1037,  1039,  1041,  1043, 17656, 17729, -2245,
   17880, 16384,  5209, 17892,  5209,  1063, 21402,  1072,  1046,  5209,
    5209,  1047, 17990, 18003,  1048,  1049, 18151, 16427, 18218,  1050,
    1051, 18249,  1052, 16466,  1054,   418, 18316, 14439,  1056, 14537,
     346,   346,   346,   346,   346,   346,   346,  1268, -2245,   565,
     565,   395, 18342,  1129,  5209,  5209,  5209,   854,   854,   346,
     -78, 21850,   371,   411,  5617,   418,  5617,   418,   -72,   -72,
     -72,  1075, 16482, 18365, 18439, 16728, 14562, 16575,  5209,  5209,
    5209, 18588,  1057, 18669, 18713, 18860, -2245, -2245,  1061, -2245,
    5209,   346,   346,   346,   346,   346,   346,   346,  1279, -2245,
     565,   565,   395, -2245,  1129,  1058,  5209,  5209,  5209,   854,
     854,   346,   -78, 21861,   371,   411,  5617,   418,  5617,   418,
     -72,   -72,   -72,  1075,   827,   827, -2245, -2245,  1195,  1310,
   -2245, -2245, -2245, -2245, -2245,    17,   484,  1227,  1228,    22,
   -2245,  1326,  1401, -2245, -2245, -2245, 23120, 20297, -2245,    44,
   -2245, 22730,  1209, -2245, -2245, -2245,   334,   613,  1068,  1330,
    1332, -2245,    30, 11988,   210,  1285,  1285,   210,   210,  1301,
   -2245, -2245,   407, -2245,  1084, 20692, 22730, -2245, -2245, -2245,
   22730, 13548,  1333,   425, -2245, -2245, 22730,  -108,   452,   425,
    2761, -2245, -2245,  1077,  9643, -2245, -2245, -2245, -2245, -2245,
   -2245,  1290,  1085, 21549, -2245, -2245, 12378,    14, -2245, -2245,
   -2245,   439, 12378, -2245, -2245, 12378, 12378,  1248,  1341,  1342,
   12378, 12378,    44,    22, -2245, 24680,    22,  1474,    22, -2245,
   -2245,  1485,    44,    44, -2245,    16,   573,    22,    22, -2245,
   -2245, -2245, 11598,   133,   767,  1093,   425,   163, 12378,  1253,
   -2245, 25291,  8863, 24680,   146,    33, -2245,  1087, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245,  8473, -2245,    32, -2245, -2245, -2245, -2245,
    1244,  1096,   210,  1290,   214,   484,  1103, -2245, -2245,  1097,
    5209, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,   -22,
   -2245, -2245,  5209, 21549, -2245, 21549, -2245,  5209,  5209, -2245,
   21358, 21358, -2245, -2245, -2245, -2245, -2245, -2245,  5209, -2245,
   -2245, -2245, -2245,  1315,  5209, -2245, -2245, -2245,  5209, -2245,
   -2245,  5209, -2245, -2245, -2245,  1129,   346, 21906,  5209, 21358,
   21358,  5209, -2245, -2245,  5209, -2245, -2245,  5209,  5209, 18904,
   18928, 18941, -2245,  1316, -2245, -2245, -2245, -2245,   395, -2245,
    1102, -2245, -2245,  1129,   346, 21961,  5209, 21358, 21358,   -38,
   -2245, -2245, -2245,  1380, -2245, -2245, -2245,   -92,  1148, -2245,
   23900, -2245, -2245, -2245, -2245,  1104, -2245,  1092, -2245,  1348,
    1007, -2245,  1170, -2245, -2245,   210,  1285,  1285,  -130,   425,
      79, -2245,  1372,  1373,    79,    25,    70, -2245, 24680, -2245,
   -2245,  1176,  -104, -2245,  1112, -2245,   456,  2761,   425, -2245,
    1122, -2245, 24680,  5209, -2245, -2245, -2245, 21549, -2245,   566,
   11988, -2245,  1132, -2245,    -7,  1119,   414, -2245, -2245, -2245,
     903,  1092, -2245,  3169, -2245, -2245, -2245,  5209,  1377,  1381,
      14, -2245,  1131,    90, -2245, -2245, 12378, -2245, -2245,    43,
   -2245, -2245, -2245, -2245,  1297, -2245,  1299, -2245, -2245,  5209,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, 11598, 24680, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245,   419, -2245, -2245, -2245, -2245, 24680, -2245, -2245, 11598,
   -2245, -2245, 25297, 24680, -2245,  1127,   421, -2245, -2245, -2245,
    1452,  1303, 24680,   484,  1260, -2245, -2245, 16699,  1199, 18959,
   21549, 21505,  1141,  1147, 14586,  1149, 19174, 19187, 19205, -2245,
    5209,   395,   827,   827, 19218, 19230, 19451, 19477, -2245, -2245,
   -2245,  1152, -2245,  1157, -2245,  5209,   395,   827,   827,  1410,
    1478,  1436,  1476,    22,    22,  1223, -2245, -2245, 21087, -2245,
    1560, -2245,  1375,    79,  1425,  1430, 11988,  1290,  5209,   210,
     210,  5209, -2245,    14,    14,    14, -2245, -2245,  1492,     7,
   22730,  1318,   103,  1371, -2245, -2245, -2245,  -108,  1344,   425,
   21549,   761,  1178, -2245,   425,  3169,  1077,  1527, -2245, -2245,
      -7, 11988, -2245, -2245,   428, 21549, 12378, -2245, -2245, 24680,
    1486,  1493, 12378, -2245, -2245, -2245, -2245, 21549,  1186,    98,
     437, -2245, 25297, -2245,  8863, -2245,   -70,  1196,  1198, -2245,
     363,   -94,  1292, -2245, -2245, -2245, -2245, -2245, -2245,  1200,
    1305, -2245,  1200, -2245, -2245, -2245, -2245, -2245, -2245,  1200,
   -2245, -2245, -2245,  1201, -2245, -2245, -2245, -2245,  1203, -2245,
    1198,   124,    -9,  1204,  1198,  1208, -2245, -2245,  2099, -2245,
      20, -2245,   449,    98,  1210, -2245,    44, -2245,  5209,  1211,
   -2245,  5209, -2245, -2245, -2245,  5209,  1042, -2245, -2245, -2245,
     395, -2245, -2245, -2245, -2245, -2245, -2245,   395,  1358,  5209,
   -2245,  1290,   498,  1447, -2245, -2245, -2245, -2245,  1367,  1465,
     210,   210,   425,  1260, 21549,    76,   639, 21549,  1213, -2245,
   -2245, -2245, -2245,  -106, -2245, -2245,  1376, -2245,  1379,  1383,
   -2245,    88, -2245,   460, -2245, -2245, -2245, -2245, -2245,  1215,
    2761,   -34, 11988,  3169,  1224,   595, -2245,    82, -2245, -2245,
   -2245,  1226,   455, -2245,  1490,   146,  5209, -2245, -2245, -2245,
   -2245,   124, -2245,    26,   130, 24680, -2245,   408, -2245,  1441,
    1442, -2245, -2245,  1321, -2245, -2245, -2245, -2245,  1229,  1444,
     470, -2245, -2245,  1231,   470,   470,  1449,  1450,   470,   496,
   -2245,  1490,  1426, -2245,  1487,  1491, -2245,   124, -2245, -2245,
    1413, -2245,  1453, -2245,  1455,   470,  1456, -2245,   470,    82,
      32,  1527, -2245, -2245, 24680, -2245,  1459, -2245, 19489, -2245,
   21549, 14605,  1247,  1252, 11598,   -44,    98,  5209,  1092,  1576,
    1578,  1554,  1583,   498, -2245,   -27, -2245,  1596,  1068,    79,
      79,  5209, -2245,  5209,  1415,  5209,  1416, 24680,  1269, -2245,
    1435, -2245, -2245, -2245, -2245,   229,  1484,    22,    22,    22,
     460, -2245, -2245, -2245, -2245,     1, -2245, -2245, -2245, -2245,
   24680, -2245,   496,   496,   496, -2245, -2245,    98, -2245, -2245,
   -2245,   662,   662,   478, -2245,  1267,  1287,    -4,   501, -2245,
   -2245, -2245, -2245,   470, -2245,    -4, -2245, -2245,  1304,  1307,
   -2245,   580, -2245, -2245, -2245, -2245, -2245,   425,  1309,  1311,
   -2245,  1275, -2245, -2245, -2245,  1312,   903,    98,  1313, -2245,
   -2245,  5209, -2245, -2245,  1476,   630,  5209, -2245, -2245, 21549,
    1324,    -4,    -4,  1597,    -4, -2245,  1598,  1600,   -27, -2245,
    1517,  1496, 21549, 21549,  1289, 21549,  1306,   512, -2245, 24290,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,   517, -2245,
     146, -2245,  1617, -2245,    94, -2245, -2245,   408, -2245, -2245,
     520, -2245, -2245,  1500, -2245,   522, -2245, -2245, 24680,    38,
      38, -2245, -2245, -2245, -2245, 19520,  1447, -2245, -2245,    98,
   24680, -2245, -2245, -2245,    -4, -2245,    -4,    -4, -2245,  1682,
    5209, 24680, 24680, -2245, 24680, -2245,   525, -2245,  1497, -2245,
   -2245, -2245, -2245, -2245, -2245,    -4,  1325, -2245, -2245, -2245,
   -2245,    82, -2245,  1577, -2245, -2245, -2245, -2245, -2245,    44,
    1685,   530,   545, -2245, -2245, 24680, -2245, -2245, -2245, -2245,
    1539,  1327,  1329,  1659, -2245, -2245, -2245, -2245,  1579, 11208,
   -2245,  1334,  1568, -2245, -2245,   564,  5209,  1335,  1336, -2245,
    1732, -2245, 21549, -2245, -2245,    22, -2245, -2245
};

/* YYPGOTO[NTERM-NUM].  */
static const short yypgoto[] =
{
   -2245, -2245, -2245, -2245, -2245, -2245,   441, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245,  -406, -2245, -2245, -1482, -2245, -2245,
   -2245,  1488, -2245,  1320,  -261, -1258, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245,   145,  -213,   462,   495,   169, -2245,
    -197, -2245,  -206, -2245, -2245,  -212,  -211, -2245, -2245, -1540,
    -248, -1272, -2245,  -472, -1340, -2245,  -338, -2245,  -375, -1348,
    -584,  -541, -2245,  -337,  -454, -2245, -1179, -2245, -2245, -1875,
    -385, -1493,  -464, -2245, -2245, -2245, -2245,   191, -2245, -2245,
   -2245,  -553,  -347,   -15, -1984, -2245, -2245, -2245, -2245,   365,
     856, -2245, -2245, -2245, -2245, -2245, -2245, -2245,   596, -2245,
   -2245, -2245, -2245, -2245,  -734,   802, -2245, -2245, -2245, -2245,
   -2245, -2245,   546,  1711,   313, -2245, -2245,  1384, -2245, -2245,
   -1165,    21, -2245,  1164,  -423,  -148,   600, -2244, -2245, -2245,
   -2245,  -158,   -10, -2245, -2245,  -808,  -497,   188, -2245, -2245,
   -2245,  -449, -2245,   776,  -412, -2245, -2245, -2245,  1338, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245,   165, -1156, -2245, -2245,
   -2245, -2245, -1456, -2245, -1394, -2245,  -937, -2245, -2245, -1361,
    -471, -2245,  -847,  1331, -1247, -2245, -2245, -1085, -2245, -2245,
   -2245, -1577,  -925, -2245, -2245, -1909, -1244, -2245, -2245,  -259,
   -1278, -1468, -2245, -2245, -2245, -2245,  -609,   614, -2245, -2245,
   -2245, -2245, -2245,  -577,  -339,  1361, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245,  1086,   861,   489, -2245, -2245,
    -581, -1639, -2245, -2245, -2245, -2245,  -272, -1213, -1487,  -123,
   -2245, -2245, -1644,  -702, -2245, -2245, -2245,  1406, -2245, -2245,
   -2245, -2245, -2245, -2245,  1110,   835, -1270,  1386, -2245, -2245,
   -2245, -2245, -2245, -2245, -2245,  -869,  -618, -2245,   900, -2245,
   -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,  1099, -2245,
   -2245, -2245, -2245, -2245,   931, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245,   123,  -441, -2245,  -349,  -500, -2245,  -451,
   -2245,  -297,  -681, -1932,  -113,   936, -1946,  -476, -1481,     0,
      -2,  -358,  -871, -2245, -2245, -2245, -2245, -2245,   602, -2245,
     317,   318,    81, -2245,   -89, -1687, -2245, -2245,   975, -2245,
     669, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245, -2245,
   -2245, -2245, -2245, -2245,  1439, -2245,   909, -2245, -2245, -2245,
   -2245, -2245,  -350, -2245,   906,   337,   -71,  -256, -2245,   113,
   -2245, -2245, -2245,  -352, -2245, -2245, -2245, -2245, -2245, -2245,
   -1727,  -602, -2245, -2001, -2245, -2245, -2245
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, parse error.  */
#define YYTABLE_NINF -1282
static const short yytable[] =
{
     245,   741,   244,   891,   370,   485,   486,   487,   954,   994,
     559,  1716,   725,  1534,   728,   729,   730,   731,   909,   883,
     386,   885,  1598,  1599,  1517,  1601,  1747,  1475,  1520,  1466,
    1580,   800,  1722,  1172,  1202,   -67,  1854,  1292,   407,  1204,
     750,   751,  1765,  1942,  1617,  1207,   788,  1606,  1471,  1782,
    1139,  -143,  1419,  1521,  1521,  1775,  1487,   651,  2064,  1489,
    1926,  1775,  1613,  1858,  1783,  1784,   245, -1186,   413,  1788,
    1789,   746,   748,  2139,  2092,  1489,   854,    23,   921,   922,
    1521,   753,   864,  1550,  1790, -1281,  2209,  1185,  1232,  1823,
    1185, -1236,  1569,  2166,  1797,  1798,   963,  1828,  1316,  1893,
    1847,  1176,  1733,  2103,  2155,   939,  1514,  1186,   415,   574,
    1489,  2216,   720,  1489,   266,   574,  1515,  1919,  1800,   690,
    2139,  1845,  2104,  1217, -1185,  1938,  1777,   392,  1950,  1944,
     951,   685,  1316,  1256,  1749,   916,  2189,   827,   996,   588,
     901,  -143,   999,   827,  1535,   385,  1536,  2396,  2253,  1174,
    2217,  2219,   456,  1538,  2129,   498,  1615,   964,   721,  1570,
    2396,   247,  2215,  2194,  1539,  1591,  2221,  1490,  1836,  1824,
    1847,  -143,   926,  1491,  1537,  2097,   828,  2115,  1725,   588,
     599,   526,   828,  1490,   457,   253,   691,  1538,  1218,  1491,
     653,  1707,  1913,   724,   600,   578,  2351,  2075,  1539,  2242,
     394,  2222,  2130,  2098,  1592,   927,   829,  2276,  1914,  1492,
    2116,   458,   829,   395,  2277,   267,   784,  1911,  1490,  1703,
    2265,  1490,  1200,  1522,  1491,  1492,  2131,  1491,   268,  2220,
    2223,   830,  -829,  1317,  1593,  1809,   378,   830,   952,   902,
    2065,   414,  1177,  1810,  2066,  1187,   820,   917,  1750,  1839,
    2190,   965,  -143,  1811,  1523,  1523,   405,  2268,   966,  1594,
    1492,  1494,  2140,  1492,   438,  1837,   439,  1317,  2183,   967,
    1493,   468,  -694,  2067,  1178,  1791,  1906,  1494,  1793,  1391,
    1795,   478,  1825,  2352,   409,  1912,   968,  1801,  1805,  1806,
    1807,  2085,   269,  1953,  1205,  1176,  2141,   416,  1664,   491,
    1210,  2088,  1920,  1055,  -143,  1775,  1753,   920,  2299,  2140,
     393,  2132,  1494,  2133,  1894,  1494,  2349,   831,   417,  1951,
    2329,   517,  1848,   831,  -694,   587,  1571, -1186,  2134,  1915,
    2053,   587,  1904,  1905,  2105,  2298,  1472,   889,  1730,  1485,
     601,  1734,  1735,  1117,  1617,  1595, -1186,   947,  2323,  1691,
    1443,  1826, -1236,   550,   551,   552,   553,  2076,  1776,  1137,
    2379,   864,  2266,   569,   570,   554,   558,   560,  1855,  1188,
     968,  1495,  1188,   410,   379,  -694,  1726,   245,  -829,   594,
    2135,   947,   853,  1310, -1185,   968,  1496,  1495,   569,   570,
     968,  1727,  1848,  2203,   245,  2142,  1458,  1937,  1524,  2068,
    2069,  1812,  1496, -1185,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,   430,   968,   695,   245,   245,   696,
    2364,    42,  1495,   701,  2151,  1495,   703,   704,   569,   570,
     709,  1497,  1516,  1607,  1514,   855,  1177,  1496,   411,   714,
    1496,  1133,  2124,  1608,  1515,   856,  1609,  1497,  1459,  2125,
     249,   250,   727,  2091,  -143,  1765,  1853,   732,   910,   733,
     734,   735,   736,   737,  2168,  1775,  2066,  1435,  1178,  1384,
     743,   744,   745,  1899,  -829,   419,   590,  1436,   749,   911,
    1129,  1907,  1497,   418,   754,  1497,   963,   756,   899,   423,
     758,   759,   760,   761,   762,   763,   764,   765,   766,  1460,
     781,   782,   783,   591,   785,   786,   787,   857,   790,   791,
     792,   793,   794,   795,   796,   797,  1908,   798,  1489,   802,
     803,   804,   805,   806,   807,   808,   812,  1943,  2152,  2322,
     421,  1385,  1777,   574,   822,  1927,   824,   825,   826,  1437,
     572,   592,   431,   643,   834,  1339,  1971,   964,  2157,  1972,
     573,   841,   842,   843,   844,   845,   846,   847,   574,   850,
     851,   852,  1778,   644,   900,   859,   860,   861,   862,  1903,
     865,   866,   868,   870,   871,   872,   873,   874,  1667,   835,
    1869,  2103,   574,   424,  1383,  -694,  1483,   875,  2196,  1484,
     864,   690,  1322,   245,   245,   880,   245,   254,   574,   858,
    2104,  1948,   888,  1335,  1336,   574,  2015,   947,  1884,   836,
    2169,  2170,   577,   578,  1212,  2044,  2045,  1720,  1213,   941,
    -829,  2068,  2069,  1386,  1348,  1616,  1490,  1467,  1468,  1293,
    1695,  1438,  1491,  1354,  1976,  2197,  2198,  2199,   578,  1359,
     606,   965,   390,  1779,   391,  1748,  1364,  1489,   966,   942,
     255,  1368,  1736,   245,   245,  1434,  1292,   256,   691,   967,
    2128,   864,   578,  -250,  2145,  2327,  2112,  1999,  1492,  2255,
    1922,  1535,  1222,  1489,  1223,   607,  1923,  1224,   578,   245,
     245,   938,   426,   837,   245,   578,  1924,   955,  2328,  1326,
     956,   428,   959,  2171,   827,  1780,  1454,  1455,  1548,   429,
     245,   608,   984,   989,   579,   988,  1545,  1546,   440,  1551,
     245,   442,   995,   245,  1538,   460,  2080,   245,   245,   461,
    1494,  2083,  2281,   943,  1418,  1539,   815,   816,   817,   818,
     819,   462,  1578,   828,  2059,  2059,  2059,  1026,   295,  2172,
     580,   581,   582,   583,   584,   585,   586,  1256,   463,   587,
    1606,  2301,   574,  2055,  2056,  1490,   647,   648,   464,   650,
    2318,  1491,  2229,   829,   256,   465,   581,   582,   583,   584,
     585,   586,  2230,   848,   587,   849,  2231,  -127,   466,  1549,
     257,  1490,  1802,  1803,  1377,   467,  1378,  1491,   830,   580,
     581,   582,   583,   584,   585,   586,   469,  1492,   587,  1105,
    1105,  1105,   609,  1428,   470,  1429,   471,   582,   583,   584,
     585,   586,  1737,  1738,   587,   589,   584,   585,   586,  1940,
    1941,   587,   588,  1492,  1963,  1964,  2008,  1964,   472,  1130,
    1495,  2185,   578,  2090,   711,   473,   558,   474,  1131,  2181,
     479,   258,  2100,   968,   480,  1496,   481,  1138,  1814,  1494,
    2302,   482,  2236,  2237,  2153,  2154,  2240,  1167,   483,  1168,
    2211,  2154,   484,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,  2250,   831,  1494,  2252,   488,  1327,   489,
    1519,  1328,  1329,  2307,  2154,  1194,  2303,  1665,   597,   864,
    1497,  2304,   490,  1196,  2179,  2180,   245,   493,  1199,  1330,
    1815,  2383,   604,   558,  1331,   653,  2312,  2313,   494,  1332,
    1816,  1206,   495,   245,  1817,  1208,  2205,  2343,  2344,  2293,
    2294,  2295,  2348,  2154,  2270,  2354,  2355,  2357,  2355,   571,
    2374,  2375,  1227,   497,  1226,  2385,  2344,   499,  1227,  1693,
    1226,   864,   500,  1239,   245,   501,  1818,  1819,   502,  1820,
    2386,  2344,   610,   611,   612,   613,   614,   615,   503,  1495,
     504,   582,   583,   584,   585,   586,   245,   505,   587,  2401,
    1941,  2359,  2360,   506,  1496,  1107,  1108,  2061,  2062,   251,
    2371,  2372,   700,   507,   245,  1495,  1307,   508,   709,   509,
    1314,   380,   381,  1321,   383,   510,   511,  1324,   512,   572,
    1496,   711,  1325,   513,   397,   514,   399,   400,  1337,   573,
    1338,   402,   403,  1340,  1341,   515,   518,  1729,  1721,  1497,
    1343,  1690,   519,   520,  1346,   521,   522,   523,   524,   525,
     527,   528,  1352,   529,  1353,   530,   531,   532,  1356,  1357,
    1358,   574,   533,   712,  1361,  1497,   534,  1363,  1769,  1365,
     535,  1366,  1367,   536,  1369,   537,   538,   539,   540,  1370,
    1371,  1372,  1373,  1374,  1375,  1376,   713,  1379,  1380,  1381,
    1382,   577,   541,  1387,  1388,  1389,  1390,   542,  1392,  1393,
    1395,  1397,  1398,  1399,  1400,  1401,   543,  1402,  1403,   544,
    1404,   545,  1405,  1406,  1407,   546,   547,   548,   549,  1411,
     716,   717,  1901,   972,   973,   974,   975,   976,   977,   978,
    1413,   979,   980,  1414,  1415,   718,   721,   739,   742,   752,
     755,   578,   757,  1718,  -596,   823,   839,  2407,   853,   840,
    1421,  1422,  1423,  1424,  1425,  1426,  1427,   876,  1430,  1431,
    1432,   877,   879,   886,  1439,  1440,  1441,  1442,   884,  1444,
    1445,  1447,  1449,  1450,  1451,  1452,  1453,   887,   889,   892,
     897,   898,   903,   579,   905,   906,   907,  1456,   891,  1862,
    1863,   245,   908,   880,  1245,  1246,  1247,  1248,   914,  1249,
    1250,  1251,  1252,   915,   919,   918,   923,   925,   929,   932,
     931,   934,   935,   940,   950,   983,   986,   990,  1872,  1873,
     997,   992,  1002,  1005,  1006,  1008,  1009,   245,  1010,  1486,
    1011,  1488,  1019,  1020,   245,  1050,  1499,  1021,  1501,  1025,
    1028,  1031,  1032,  1035,  1059,  1111,  1887,  1888,   245,   245,
     938,  1508,  1124,  1112,  1126,  1113,   558,  1114,  1115,  1116,
     767,   768,   769,   770,  1134,  1960,  1533,  1127,   580,   581,
     582,   583,   584,   585,   586,  1128,  1132,   587,   771,   772,
     773,  1136,   574,  1169,  1170,  1171,  1173,  1175,  1183,  1197,
     774,   775,  1203,  1219,   776,  1220,  1230,  1231,  1234,  1256,
    1883,  1295,  1296,   777,  1934,  1297,  1298,  1253,  1587,  1299,
    1300,  1301,  1302,  1303,  1304,  1306,  1312,  1319,   968,  1323,
     778,   779,  1342,     1,  -694,     2,  1344,  1349,  1614,  1350,
     690,  1351,  1355,  1408,  1409,  1360,  1362,  1410,  1412,  1416,
    1417,  1433,  1457,     3,     4,  1463,     5,  1186,     6,  1185,
    1477,     7,  1633,     8,  1635,  -694,     9,    10,    11,  1640,
    1641,    12,    13,  1478,    14,    15,  1479,    16,  -694,  1481,
    1482,  1500,    17,    18,    19,  1504,    20,    21,  1505,    22,
      23,    24,    25,  1506,    26,  1510,    27,  1512,  1513,    28,
      29,    30,  1509,  1547,  1187,  1666,   443,   691,  1552,  1553,
      31,  2207,  1535,  1556,  1669,  1557,  1670,  1558,  1559,  1560,
     444,  1562,  1561,    32,  1563,  1564,  1565,  1566,  1679,  1680,
    1681,  1567,  1568,  1573,  1574,    33,    34,  1575,  1576,  1577,
    1688,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,  1579,  1588,  -694,  1589,  1581,  1590,  1694,    35,  1597,
    2052,  1612,  -694,  -694,  1600,   445,  1697,  1616,  1698,  -694,
    1622,  1623,  1624,  -694,  1625,  -694,  1626,  1636,  1627,  -694,
    1638,  1639,  1642,  1645,  1646,  1650,  1651,  1662,  1653,  1655,
    1700,  1659,  1692,  1683,   446,  1769,  1687,  1701,  1689,  1704,
    1705,  1708,  1709,  1719,  1713,  1715,  1213,   571,  1723,   558,
    1724,  1761,  1739,  1794,  1731,  -694,  1746,   447,  1274,  1773,
    1785,  1786,  1787,  -694,  1796,  1829,  1851,  1822,  1843,  -694,
    1852,  1313,  1856,   695,   558,  1865,  1881,  1882,   558,  1239,
    1757,  1890,  1895,  1900,   558,  1898,  1902,  1918,  1920,    36,
    1909,  1910,  1196,    37,  1939,    38,  1928,  1946,  2009,    39,
    -694,  1947,  2007,   448,  1587,  1949,   449,  -694,  1936,  1955,
    1587,  1956,  2016,  1587,  1587,  2011,  2022,   572,  1587,  1587,
     450,  2019,  2023,  1792,  2038,  2026,  -694,   573,  2035,    40,
    -694,  -694,  2036,   451,  -694,  2039,   452,   250,  2040,  2048,
     245,  2042,  1808,  2050,  2049,  2046,  1587,  2162,  2051,  2063,
    1587,  1835,  2073,  -694,  2082,  2077,  2079,  1521,  2093,   574,
    2332,  2333,  2096,  2335,  2122,  2094,  2117,  2164,   575,   576,
    2109,  1587,  2110,  2175,  2119,  2126,  1934,  2127,  2144,  2177,
    1857,   284,  2146,  2178,  2156,  2243,  2159,  2187,  2191,   577,
    2202,  2192,  1859,  2163,   286,  2193,  2141,  1860,  1861,  2208,
    2210,  2225,  2226,  2227,  2228,  2235,  -694,  2244,  1864,  2238,
    2239,  2245,  2247,  2248,  1866,  2249,  2251,  -694,  1867,  2258,
     289,  1868,  2262,  2366,   891,  2367,  2368,  2263,  1871,  -694,
      41,  1874,  -694,  2271,  1875,  2272,  2273,  1876,  1877,   578,
    2274,  2280,  2308,  2289,  2377,  2284,  2286,  2290,  2292,   292,
     293,  2313,  2330,  2339,  2334,  2336,  1886,  2337,  2340,  2350,
    2356,  2369,  2309,  2341,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,    42,   294,  -694,  -694,  1897,  2316,
    2342,   579,  2317,  1839,  2319,  2380,  2320,  2321,  2324,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,  2388,
    2378,  2389,   295,  2391,  2392,  2393,  1501,  1757,  2400,  -742,
    2403,  2405,  2404,  1930,  2254,  1602,   702,  2150,  1846,   427,
    1239,  2102,  1584,  1540,  1840,  2095,  2101,  2147,  2113,  2114,
     571,  2314,  2246,  2218,  2376,  2212,  2353,  1945,  2306,  2257,
    2224,  2315,  1830,  1294,  1954,  1211,  1507,  1464,  1702,   412,
    1931,   896,  2297,  2081,  1587,   571,  2213,  2214,  1470,  1957,
    1334,   305,   726,   688,  2182,  2406,   580,   581,   582,   583,
     584,   585,   586,   715,  1474,   587,  1001,  1242,  2395,  1618,
    2206,  1125,   738,  2086,   687,   987,  1209,   998,  1182,   710,
     245,  1961,  1889,  2326,  2275,  1311,  2363,  2338,  2089,  1745,
     572,  1195,  2241,  1929,  1965,  1752,  1511,   245,  2078,  1966,
     573,  2006,  1462,   683,  1229,  2291,  1233,  1744,  2296,  2072,
    2014,  1917,     0,     0,     0,   572,     0,     0,     0,     0,
    2030,     0,     0,     0,     0,   573,     0,     0,     0,     0,
       0,     0,   574,     0,     0,  2037,     0,     0,     0,     0,
       0,   575,   576,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  1456,   574,  2054,     0,
       0,  2057,   577,     0,     0,     0,   575,   576,     0,     0,
       0,     0,     0,  1769,     0,   485,   486,   487,   558,     0,
       0,     0,     0,     0,     0,     0,     0,   577,     0,     0,
       0,     0,     0,     0,   619,     0,     0,     0,     0,  1196,
     620,     0,     0,     0,  1587,     0,     0,  2014,     0,     0,
    1587,  1261,   578,     0,     0,   621,     0,     0,     0,     0,
       0,     0,  1587,     0,     0,     0,     0,     0,     0,   622,
       0,     0,     0,     0,     0,     0,     0,   578,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
       0,     0,     0,     0,   579,     0,     0,     0,     0,  1263,
    1264,     0,     0,     0,     0,     0,     0,   623,  2158,     0,
       0,  2160,  1265,  1266,     0,  2161,     0,     0,     0,   579,
       0,     0,  1267,     0,     0,  1268,     0,     0,     0,  1957,
       0,     0,   624,     0,   625,     0,   626,     0,     0,     0,
       0,     0,     0,     0,   571,     0,   627,   628,     0,     0,
     629,     0,     0,     0,     0,     0,   630,     0,     0,     0,
    1271,     0,     0,     0,   631,     0,   632,     0,     0,     0,
    1757,     0,     0,     0,     0,     0,     0,     0,     0,   580,
     581,   582,   583,   584,   585,   586,  1957,     0,   587,     0,
       0,     0,   633,  1109,  2384,  1272,     0,     0,     0,     0,
     634,     0,  1273,  2014,   580,   581,   582,   583,   584,   585,
     586,     0,     0,   587,   572,  1017,  1018,     0,     0,     0,
       0,     0,     0,  1275,   573,     0,     0,     0,     0,  1261,
       0,     0,  1276,  1277,  1278,     0,     0,     0,   635,     0,
       0,     0,   636,     0,     0,   637,   638,     0,  1280,     0,
       0,     0,  2014,     0,     0,     0,   574,  2269,     0,     0,
       0,     0,   245,     0,  2264,   575,   576,  1281,     0, -1141,
       0,  2282,     0,  2283,     0,  2285,  1282,  1263,  1264,     0,
       0,     0,     0,     0,     0,  2288,   577,     0,     0,     0,
    1265,  1266,  1283,     0,     0,     0,     0,     0,     0,     0,
    1267,     0,     0,  1268,     0,     0,     0,     0,  2014,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   578,     0,  1271,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  2325,     0,     0,     0,     0,  1957,     0,     0,     0,
       0,     0,     0,     0,  1284,     0,     0,     0,     0,     0,
       0,     0,     0,  1272,     0,     0,     0,  1286,   579,     0,
    1273,     0,     0,     0,     0,     0,     0,  2347,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  1275,     0,     0,     0,     0,     0,     0,     0,     0,
    1276,  1277,  1278,     0,     0,     0,  2358,     0,     0,     0,
       0,     0,     0,     0,     0,  1603,  1280,     0,  2365,     0,
    2370,     0,     0,     0,     0,     0,     0,     0,     0,  2288,
    2288,     0,  2373,     0,     0,  1281,     0,     0,     0,     0,
       0,     0,     0,     0,  1282,     0,     0,    85,    86,    87,
      88,    89,     0,   580,   581,   582,   583,   584,   585,   586,
    1283,     0,   587,  2387,  1110,    90,     0,     0,   273,    92,
      93,     0,    94,    95,    96,   274,  2402,  1196,    97,     0,
      98,     0,    99,   100,   101,   275,   102,     0,     0,   103,
       0,   104,   276,   277,   105,     0,     0,   106,   107,   108,
     109,   110,   111,     0,     0,   112,   113,   114,   278,   115,
     279,   116,   280,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,   281,   124,   125,   126,   809,
       0,   127,  1284,   282,   128,   129,     0,   130,     0,     0,
     131,     0,   283,     0,   132,  1286,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,   284,     0,     0,     0,   144,     0,
     145,     0,   146,   285,     0,     0,   147,   286,     0,   148,
     149,     0,     0,   150,     0,     0,   151,     0,     0,   152,
     153,     0,     0,     0,   810,   287,   154,     0,     0,     0,
     155,   288,   156,   289,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,   290,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
     291,   178,   292,   293,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,   294,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,   295,     0,   811,   204,   205,
     296,   297,   298,   299,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,   300,   212,   301,   213,   302,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   303,
     304,     0,     0,     0,   305,     0,     0,     0,     0,     0,
     223,   306,     0,   307,   308,   309,   310,   311,   312,   313,
     314,   315,   316,     0,     0,     0,   224,   317,   318,   319,
       0,   320,   321,   322,   323,   324,   325,   326,     0,   327,
     328,     0,     0,   329,   226,   330,   227,   331,   332,   333,
     334,   335,   336,     0,   337,   229,   230,   338,   339,   340,
     341,     0,   342,   343,   344,   345,   346,   234,   347,   348,
     349,   350,   351,   352,   353,   354,   355,   356,   357,   358,
     359,     0,   235,     0,   360,   361,   362,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,     0,     0,   363,
       0,     0,     0,     0,   364,     0,     0,   365,     0,     0,
     366,   367,     0,   368,   369,    85,    86,    87,    88,    89,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    90,     0,     0,   273,    92,    93,     0,
      94,    95,    96,   274,     0,     0,    97,     0,    98,     0,
      99,   100,   101,   275,   102,     0,     0,   103,     0,   104,
     276,   277,   105,     0,     0,   106,   107,   108,   109,   110,
     111,     0,     0,   112,   113,   114,   278,   115,   279,   116,
     280,     0,     0,   118,   119,  1754,     0,     0,     0,   120,
     121,   122,   123,   281,   124,   125,   126,     0,     0,   127,
       0,   282,   128,   129,     0,   130,     0,     0,   131,     0,
     283,     0,   132,  1755,     0,   133,     0,     0,   134,   135,
       0,   136,   137,     0,     0,   138,   139,     0,   140,   141,
     142,   143,   284,     0,     0,     0,   144,     0,   145,     0,
     146,   285,     0,     0,   147,   286,     0,   148,   149,     0,
       0,   150,     0,     0,   151,     0,     0,   152,   153,     0,
       0,     0,     0,   287,   154,     0,     0,     0,   155,   288,
     156,   289,     0,     0,   157,   158,   159,   160,   161,   162,
     163,     0,   164,   165,   290,   166,   167,   168,   169,   170,
     171,   172,   173,   174,   175,     0,   176,   177,   291,   178,
     292,   293,   179,  1756,   180,     0,     0,     0,     0,     0,
       0,     0,   181,   182,     0,     0,     0,   183,   184,   185,
     186,   187,   188,   189,   190,     0,   294,     0,     0,   191,
       0,   192,     0,   193,   194,     0,     0,   195,   196,   197,
       0,   198,   199,   200,     0,     0,   201,     0,   202,     0,
       0,   203,     0,   295,     0,     0,   204,   205,   296,   297,
     298,   299,     0,     0,   206,   207,     0,     0,     0,   208,
       0,     0,     0,   209,     0,     0,     0,   210,     0,   211,
       0,     0,   300,   212,   301,   213,   302,     0,     0,   215,
     216,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   217,     0,   218,     0,   219,   220,   303,   304,     0,
       0,     0,   305,     0,     0,     0,     0,     0,   223,   306,
       0,   307,   308,   309,   310,   311,   312,   313,   314,   315,
     316,     0,     0,     0,   224,   317,   318,   319,     0,   320,
     321,   322,   323,   324,   325,   326,     0,   327,   328,     0,
       0,   329,   226,   330,   227,   331,   332,   333,   334,   335,
     336,     0,   337,   229,   230,   338,   339,   340,   341,     0,
     342,   343,   344,   345,   346,   234,   347,   348,   349,   350,
     351,   352,   353,   354,   355,   356,   357,   358,   359,     0,
     235,     0,   360,   361,   362,   237,     0,     0,   238,     0,
     239,     0,   240,   241,   242,     0,     0,   363,     0,     0,
       0,     0,   364,     0,     0,   365,     0,     0,   366,   367,
       0,   368,   369,    85,    86,    87,    88,    89,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    90,     0,     0,   273,    92,    93,     0,    94,    95,
      96,   274,     0,     0,    97,     0,    98,     0,    99,   100,
     101,   275,   102,     0,     0,   103,     0,   104,   276,   277,
     105,     0,     0,   106,   107,   108,   109,   110,   111,     0,
       0,   112,   113,   114,   278,   115,   279,   116,   280,     0,
       0,   118,   119,     0,     0,     0,     0,   120,   121,   122,
     123,   281,   124,   125,   126,     0,     0,   127,     0,   282,
     128,   129,     0,   130,     0,     0,   131,     0,   283,     0,
     132,   434,     0,   133,     0,     0,   134,   135,     0,   136,
     137,     0,     0,   138,   139,     0,   140,   141,   142,   143,
     284,     0,     0,     0,   144,     0,   145,     0,   146,   285,
       0,     0,   147,   286,     0,   148,   149,     0,     0,   150,
       0,     0,   151,     0,     0,   152,   153,     0,     0,     0,
       0,   287,   154,     0,     0,     0,   155,   288,   156,   289,
       0,     0,   157,   158,   159,   160,   161,   162,   163,     0,
     164,   165,   290,   166,   167,   168,   169,   170,   171,   172,
     173,   174,   175,     0,   176,   177,   291,   178,   292,   293,
     179,     0,   180,     0,     0,     0,     0,     0,     0,     0,
     181,   182,     0,     0,     0,   183,   184,   185,   186,   187,
     188,   189,   190,     0,   294,     0,     0,   191,     0,   192,
       0,   193,   194,     0,     0,   195,   196,   197,     0,   198,
     199,   200,     0,     0,   201,     0,   202,     0,     0,   203,
       0,   295,     0,     0,   204,   205,   296,   297,   298,   299,
       0,     0,   206,   207,     0,     0,     0,   208,     0,     0,
       0,   209,     0,     0,     0,   210,     0,   211,     0,     0,
     300,   212,   301,   213,   302,     0,     0,   215,   216,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   217,
       0,   218,     0,   219,   220,   303,   304,     0,     0,     0,
     305,     0,     0,     0,     0,     0,   223,   306,     0,   307,
     308,   309,   310,   311,   312,   313,   314,   315,   316,     0,
       0,     0,   224,   317,   318,   319,     0,   320,   321,   322,
     323,   324,   325,   326,     0,   327,   328,     0,     0,   329,
     226,   330,   227,   331,   332,   333,   334,   335,   336,     0,
     337,   229,   230,   338,   339,   340,   341,     0,   342,   343,
     344,   345,   346,   234,   347,   348,   349,   350,   351,   352,
     353,   354,   355,   356,   357,   358,   359,     0,   235,     0,
     360,   361,   362,   237,     0,     0,   238,     0,   239,     0,
     240,   241,   242,     0,     0,   363,     0,     0,     0,     0,
     364,     0,     0,   365,     0,     0,   366,   367,     0,   368,
     369,    85,    86,    87,    88,    89,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    90,
       0,     0,   273,    92,    93,     0,    94,    95,    96,   274,
       0,     0,    97,     0,    98,     0,    99,   100,   101,   275,
     102,     0,     0,   103,     0,   104,   276,   277,   105,     0,
       0,   106,   107,   108,   109,   110,   111,     0,     0,   112,
     113,   114,   278,   115,   279,   116,   280,     0,     0,   118,
     119,     0,     0,     0,     0,   120,   121,   122,   123,   281,
     124,   125,   126,     0,     0,   127,     0,   282,   128,   129,
       0,   130,     0,     0,   131,     0,   283,     0,   132,     0,
       0,   133,     0,     0,   134,   135,     0,   136,   137,     0,
       0,   138,   139,     0,   140,   141,   142,   143,   284,     0,
       0,     0,   144,     0,   145,     0,   146,   285,     0,     0,
     147,   286,     0,   148,   149,     0,     0,   150,     0,     0,
     151,     0,     0,   152,   153,     0,     0,     0,     0,   287,
     154,     0,     0,     0,   155,   288,   156,   289,     0,     0,
     157,   158,   159,   160,   161,   162,   163,     0,   164,   165,
     290,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,     0,   176,   177,   291,   178,   292,   293,   179,     0,
     180,     0,     0,     0,     0,     0,     0,     0,   181,   182,
       0,     0,     0,   183,   184,   185,   186,   187,   188,   189,
     190,     0,   294,     0,     0,   191,     0,   192,     0,   193,
     194,     0,     0,   195,   196,   197,     0,   198,   199,   200,
       0,     0,   201,     0,   202,     0,     0,   203,     0,   295,
       0,     0,   204,   205,   296,   297,   298,   299,     0,     0,
     206,   207,     0,     0,     0,   208,     0,     0,     0,   209,
       0,     0,     0,   210,     0,   211,     0,     0,   300,   212,
     301,   213,   302,     0,     0,   215,   216,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   217,     0,   218,
       0,   219,   220,   303,   304,     0,     0,     0,   305,     0,
       0,     0,     0,     0,   223,   306,     0,   307,   308,   309,
     310,   311,   312,   313,   314,   315,   316,     0,     0,     0,
     224,   317,   318,   319,     0,   320,   321,   322,   323,   324,
     325,   326,     0,   327,   328,     0,     0,   329,   226,   330,
     227,   331,   332,   333,   334,   335,   336,     0,   337,   229,
     230,   338,   339,   340,   341,     0,   342,   343,   344,   345,
     346,   234,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,     0,   235,     0,   360,   361,
     362,   237,     0,     0,   238,     0,   239,     0,   240,   241,
     242,     0,     0,   363,     0,     0,     0,     0,   364,     0,
       0,   365,   755,     0,   366,   367,     0,   368,   369,    85,
      86,    87,    88,    89,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    90,     0,     0,
     273,    92,    93,     0,    94,    95,    96,   274,     0,     0,
      97,     0,    98,     0,    99,   100,   101,   275,   102,     0,
       0,   103,     0,   104,   276,   277,   105,     0,     0,   106,
     107,   108,   109,   110,   111,     0,     0,   112,   113,   114,
     278,   115,   279,   116,   280,     0,     0,   118,   119,     0,
       0,     0,     0,   120,   121,   122,   123,   281,   124,   125,
     126,     0,     0,   127,     0,   282,   128,   129,     0,   130,
       0,     0,   131,     0,   283,     0,   132,     0,     0,   133,
       0,     0,   134,   135,     0,   136,   137,     0,     0,   138,
     139,     0,   140,   141,   142,   143,   284,     0,     0,     0,
     144,     0,   145,     0,   146,   285,     0,     0,   147,   286,
       0,   148,   149,     0,     0,   150,     0,     0,   151,     0,
       0,   152,   153,     0,     0,     0,     0,   287,   154,     0,
       0,     0,   155,   288,   156,   289,     0,     0,   157,   158,
     159,   160,   161,   162,   163,     0,   164,   165,   290,   166,
     167,   168,   169,   170,   171,   172,   173,   174,   175,     0,
     176,   177,   291,   178,   292,   293,   179,     0,   180,     0,
       0,     0,     0,     0,     0,     0,   181,   182,     0,     0,
       0,   183,   184,   185,   186,   187,   188,   189,   190,     0,
     294,     0,     0,   191,     0,   192,     0,   193,   194,     0,
       0,   195,   196,   197,     0,   198,   199,   200,     0,     0,
     201,     0,   202,     0,     0,   203,     0,   295,     0,     0,
     204,   205,   296,   297,   298,   299,     0,     0,   206,   207,
       0,     0,     0,   208,     0,     0,     0,   209,     0,     0,
       0,   210,     0,   211,     0,     0,   300,   212,   301,   213,
     302,     0,     0,   215,   216,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   217,     0,   218,     0,   219,
     220,   303,   304,     0,     0,     0,   305,     0,     0,     0,
       0,     0,   223,   306,     0,   307,   308,   309,   310,   311,
     312,   313,   314,   315,   316,     0,     0,     0,   224,   317,
     318,   319,     0,   320,   321,   322,   323,   324,   325,   326,
       0,   327,   328,     0,     0,   329,   226,   330,   227,   331,
     332,   333,   334,   335,   336,     0,   337,   229,   230,   338,
     339,   340,   341,     0,   342,   343,   344,   345,   346,   234,
     347,   348,   349,   350,   351,   352,   353,   354,   355,   356,
     357,   358,   359,     0,   235,     0,   360,   361,   362,   237,
       0,     0,   238,     0,   239,     0,   240,   241,   242,     0,
       0,   363,     0,     0,     0,     0,   364,     0,     0,   365,
     789,     0,   366,   367,     0,   368,   369,    85,    86,    87,
      88,    89,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    90,     0,     0,   273,    92,
      93,     0,    94,    95,    96,   274,     0,     0,    97,     0,
      98,     0,    99,   100,   101,   275,   102,     0,     0,   103,
       0,   104,   276,   277,   105,     0,     0,   106,   107,   108,
     109,   110,   111,     0,     0,   112,   113,   114,   278,   115,
     279,   116,   280,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,   281,   124,   125,   126,     0,
       0,   127,     0,   282,   128,   129,     0,   130,     0,     0,
     131,     0,   283,     0,   132,     0,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,   284,     0,     0,     0,   144,     0,
     145,     0,   146,   285,     0,     0,   147,   286,     0,   148,
     149,     0,     0,   150,     0,     0,   151,     0,     0,   152,
     153,     0,     0,     0,     0,   287,   154,     0,     0,     0,
     155,   288,   156,   289,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,   290,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
     291,   178,   292,   293,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,   294,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,   295,     0,     0,   204,   205,
     296,   297,   298,   299,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,   300,   212,   301,   213,   302,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   303,
     304,     0,     0,     0,   305,     0,     0,     0,     0,     0,
     223,   306,     0,   307,   308,   309,   310,   311,   312,   313,
     314,   315,   316,     0,     0,     0,   224,   317,   318,   319,
       0,   320,   321,   322,   323,   324,   325,   326,     0,   327,
     328,     0,     0,   329,   226,   330,   227,   331,   332,   333,
     334,   335,   336,     0,   337,   229,   230,   338,   339,   340,
     341,     0,   342,   343,   344,   345,   346,   234,   347,   348,
     349,   350,   351,   352,   353,   354,   355,   356,   357,   358,
     359,     0,   235,     0,   360,   361,   362,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,     0,     0,   363,
       0,     0,     0,     0,   364,     0,     0,   365,   801,     0,
     366,   367,     0,   368,   369,    85,    86,    87,    88,    89,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    90,     0,     0,   273,    92,    93,     0,
      94,    95,    96,   274,     0,     0,    97,     0,    98,     0,
      99,   100,   101,   275,   102,     0,     0,   103,     0,   104,
     276,   277,   105,     0,     0,   106,   107,   108,   109,   110,
     111,     0,     0,   112,   113,   114,   278,   115,   279,   116,
     280,     0,     0,   118,   119,     0,     0,     0,     0,   120,
     121,   122,   123,   281,   124,   125,   126,     0,     0,   127,
       0,   282,   128,   129,     0,   130,     0,     0,   131,     0,
     283,     0,   132,     0,     0,   133,     0,     0,   134,   135,
       0,   136,   137,     0,     0,   138,   139,     0,   140,   141,
     142,   143,   284,     0,     0,     0,   144,     0,   145,     0,
     146,   285,     0,     0,   147,   286,     0,   148,   149,     0,
       0,   150,     0,     0,   151,     0,     0,   152,   153,     0,
       0,     0,     0,   287,   154,     0,     0,     0,   155,   288,
     156,   289,     0,     0,   157,   158,   159,   160,   161,   162,
     163,     0,   164,   165,   290,   166,   167,   168,   169,   170,
     171,   172,   173,   174,   175,     0,   176,   177,   291,   178,
     292,   293,   179,     0,   180,     0,     0,     0,     0,     0,
       0,     0,   181,   182,     0,     0,     0,   183,   184,   185,
     186,   187,   188,   189,   190,     0,   294,     0,     0,   191,
       0,   192,     0,   193,   194,     0,     0,   195,   196,   197,
       0,   198,   199,   200,     0,     0,   201,     0,   202,     0,
       0,   203,     0,   295,     0,     0,   204,   205,   296,   297,
     298,   299,     0,     0,   206,   207,     0,     0,     0,   208,
       0,     0,     0,   209,     0,     0,     0,   210,     0,   211,
       0,     0,   300,   212,   301,   213,   302,     0,     0,   215,
     216,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   217,     0,   218,     0,   219,   220,   303,   304,     0,
       0,     0,   305,     0,     0,     0,     0,     0,   223,   306,
       0,   307,   308,   309,   310,   311,   312,   313,   314,   315,
     316,     0,     0,     0,   224,   317,   318,   319,     0,   320,
     321,   322,   323,   324,   325,   326,     0,   327,   328,     0,
       0,   329,   226,   330,   227,   331,   332,   333,   334,   335,
     336,     0,   337,   229,   230,   338,   339,   340,   341,     0,
     342,   343,   344,   345,   346,   234,   347,   348,   349,   350,
     351,   352,   353,   354,   355,   356,   357,   358,   359,     0,
     235,     0,   360,   361,   362,   237,     0,     0,   238,     0,
     239,     0,   240,   241,   242,     0,     0,   363,     0,     0,
       0,     0,   364,     0,     0,   365,   821,     0,   366,   367,
       0,   368,   369,    85,    86,    87,    88,    89,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    90,     0,     0,   273,    92,    93,     0,    94,    95,
      96,   274,     0,     0,    97,     0,    98,     0,    99,   100,
     101,   275,   102,     0,     0,   103,     0,   104,   276,   277,
     105,     0,     0,   106,   107,   108,   109,   110,   111,     0,
       0,   112,   113,   114,   278,   115,   279,   116,   280,     0,
       0,   118,   119,     0,     0,     0,     0,   120,   121,   122,
     123,   281,   124,   125,   126,     0,     0,   127,     0,   282,
     128,   129,     0,   130,     0,     0,   131,     0,   283,     0,
     132,     0,     0,   133,     0,     0,   134,   135,     0,   136,
     137,     0,     0,   138,   139,     0,   140,   141,   142,   143,
     284,     0,     0,     0,   144,     0,   145,     0,   146,   285,
       0,     0,   147,   286,     0,   148,   149,     0,     0,   150,
       0,     0,   151,     0,     0,   152,   153,     0,     0,     0,
       0,   287,   154,     0,     0,     0,   155,   288,   156,   289,
       0,     0,   157,   158,   159,   160,   161,   162,   163,     0,
     164,   165,   290,   166,   167,   168,   169,   170,   171,   172,
     173,   174,   175,     0,   176,   177,   291,   178,   292,   293,
     179,     0,   180,     0,     0,     0,     0,     0,     0,     0,
     181,   182,     0,     0,     0,   183,   184,   185,   186,   187,
     188,   189,   190,     0,   294,     0,     0,   191,     0,   192,
       0,   193,   194,     0,     0,   195,   196,   197,     0,   198,
     199,   200,     0,     0,   201,     0,   202,     0,     0,   203,
       0,   295,     0,     0,   204,   205,   296,   297,   298,   299,
       0,     0,   206,   207,     0,     0,     0,   208,     0,     0,
       0,   209,     0,     0,     0,   210,     0,   211,     0,     0,
     300,   212,   301,   213,   302,     0,     0,   215,   216,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   217,
       0,   218,     0,   219,   220,   303,   304,     0,     0,     0,
     305,     0,     0,     0,     0,     0,   223,   306,     0,   307,
     308,   309,   310,   311,   312,   313,   314,   315,   316,     0,
       0,     0,   224,   317,   318,   319,     0,   320,   321,   322,
     323,   324,   325,   326,     0,   327,   328,     0,     0,   329,
     226,   330,   227,   331,   332,   333,   334,   335,   336,     0,
     337,   229,   230,   338,   339,   340,   341,     0,   342,   343,
     344,   345,   346,   234,   347,   348,   349,   350,   351,   352,
     353,   354,   355,   356,   357,   358,   359,     0,   235,     0,
     360,   361,   362,   237,     0,     0,   238,     0,   239,     0,
     240,   241,   242,     0,     0,   363,     0,     0,     0,     0,
     364,     0,     0,   365,     0,     0,   366,   367,     0,   368,
     369,    85,    86,    87,    88,    89,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    90,
       0,     0,   273,    92,    93,     0,    94,    95,    96,   274,
       0,     0,    97,     0,    98,     0,    99,   100,   101,   275,
     102,     0,     0,   103,     0,   104,   276,   277,   105,     0,
       0,   106,   107,   108,   109,   110,   111,     0,     0,   112,
     113,   114,   278,   115,   279,   116,   280,     0,     0,   118,
     119,     0,     0,     0,     0,   120,   121,   122,   123,   281,
     124,   125,   126,     0,     0,   127,     0,   282,   128,   129,
       0,   130,     0,     0,   131,     0,   283,     0,   132,     0,
       0,   133,     0,     0,   134,   135,     0,   136,   137,     0,
       0,   138,   139,     0,   140,   141,   142,   143,   284,     0,
       0,     0,   144,     0,   145,     0,   146,   285,     0,     0,
     147,   286,     0,   148,   149,     0,     0,   150,     0,     0,
     151,     0,     0,   152,   153,     0,     0,     0,     0,   287,
     154,     0,     0,     0,   155,   288,   156,   289,     0,     0,
     157,   158,   159,   160,   161,   162,   163,     0,   164,   165,
     290,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,     0,   176,   177,   291,   178,   292,   293,   179,     0,
     180,     0,     0,     0,     0,     0,     0,     0,   181,   182,
       0,     0,     0,   183,   184,   185,   186,   187,   188,   189,
     190,     0,   294,     0,     0,   191,     0,   192,     0,   193,
     194,     0,     0,   195,   196,   197,     0,   198,   199,   200,
       0,     0,   201,     0,   202,     0,     0,   203,     0,   295,
       0,     0,   204,   205,   296,   297,   298,   299,     0,     0,
     206,   207,     0,     0,     0,   208,     0,     0,     0,   209,
       0,     0,     0,   210,     0,   211,     0,     0,   300,   212,
     301,   213,   302,     0,     0,   215,   216,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   217,     0,   218,
       0,   219,   220,   303,   304,     0,     0,     0,   305,     0,
       0,     0,     0,     0,   223,   306,     0,   307,   308,   309,
     310,   311,   312,   313,   314,   315,   316,     0,     0,     0,
     224,   317,   318,   319,     0,   320,   321,   322,   323,   324,
     325,   326,     0,   327,   328,     0,     0,   329,   226,   330,
     227,   331,   332,   333,   334,   335,   336,     0,   337,   229,
     230,   338,   339,   340,   341,     0,   342,   343,   344,   345,
     346,   234,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,     0,   235,     0,   360,   361,
     362,   237,     0,     0,   238,     0,   239,     0,   240,   241,
     242,     0,     0,   363,     0,     0,     0,     0,   364,     0,
       0,   516,     0,     0,   366,   367,     0,   368,   369,    85,
      86,    87,    88,    89,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    90,     0,     0,
     273,    92,    93,     0,    94,    95,    96,   274,     0,     0,
      97,     0,    98,     0,    99,   100,   101,   275,   102,     0,
       0,   103,     0,   104,   276,   277,   105,     0,     0,   106,
     107,   108,   109,   110,   111,     0,     0,   112,   113,   114,
     278,   115,   279,   116,   280,     0,     0,   118,   119,     0,
       0,     0,     0,   120,   121,   122,   123,   281,   124,   125,
     126,     0,     0,   127,     0,   282,   128,   129,     0,   130,
       0,     0,   131,     0,   283,     0,   132,     0,     0,   133,
       0,     0,   134,   135,     0,   136,   137,     0,     0,   138,
     139,     0,   140,   141,   142,   143,   284,     0,     0,     0,
     144,     0,   145,     0,   146,   285,     0,     0,   147,   286,
       0,   148,   149,     0,     0,   150,     0,     0,   151,     0,
       0,   152,   153,     0,     0,     0,     0,   287,   154,     0,
       0,     0,   155,   288,   156,   289,     0,     0,   157,   158,
     159,   160,   161,   162,   163,     0,   164,   165,   290,   166,
     167,   168,   169,   170,   171,   172,   173,   174,   175,     0,
     176,   177,   291,   178,   292,   293,   179,     0,   180,     0,
       0,     0,     0,     0,     0,     0,   181,   182,     0,     0,
       0,   183,   184,   185,   186,   187,   188,   189,   190,     0,
     294,     0,     0,   191,     0,   192,     0,   193,   194,     0,
       0,   195,   196,   197,     0,   198,   199,   200,     0,     0,
     201,     0,   202,     0,     0,   203,     0,   295,     0,     0,
     204,   205,   296,   297,   298,   299,     0,     0,   206,   207,
       0,     0,     0,   208,     0,     0,     0,   209,     0,     0,
       0,   210,     0,   211,     0,     0,   300,   212,   301,   213,
     302,     0,     0,   215,   216,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   217,     0,   218,     0,   219,
     220,   303,   304,     0,     0,     0,   305,     0,     0,     0,
       0,     0,   223,   306,     0,   307,   308,   309,   310,   311,
     312,   313,   314,   315,   316,     0,     0,     0,   224,   317,
     318,   319,     0,   320,   321,   322,   323,   324,   325,   326,
       0,   327,   328,     0,     0,   329,   226,   330,   227,   867,
     332,   333,   334,   335,   336,     0,   337,   229,   230,   338,
     339,   340,   341,     0,   342,   343,   344,   345,   346,   234,
     347,   348,   349,   350,   351,   352,   353,   354,   355,   356,
     357,   358,   359,     0,   235,     0,   360,   361,   362,   237,
       0,     0,   238,     0,   239,     0,   240,   241,   242,     0,
       0,   363,     0,     0,     0,     0,   364,     0,     0,   365,
       0,     0,   366,   367,     0,   368,   369,    85,    86,    87,
      88,    89,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    90,     0,     0,   273,    92,
      93,     0,    94,    95,    96,   274,     0,     0,    97,     0,
      98,     0,    99,   100,   101,   275,   102,     0,     0,   103,
       0,   104,   276,   277,   105,     0,     0,   106,   107,   108,
     109,   110,   111,     0,     0,   112,   113,   114,   278,   115,
     279,   116,   280,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,   281,   124,   125,   126,     0,
       0,   127,     0,   282,   128,   129,     0,   130,     0,     0,
     131,     0,   283,     0,   132,     0,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,   284,     0,     0,     0,   144,     0,
     145,     0,   146,   285,     0,     0,   147,   286,     0,   148,
     149,     0,     0,   150,     0,     0,   151,     0,     0,   152,
     153,     0,     0,     0,     0,   287,   154,     0,     0,     0,
     155,   288,   156,   289,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,   290,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
     291,   178,   292,   293,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,   294,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,   295,     0,     0,   204,   205,
     296,   297,   298,   299,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,   300,   212,   301,   213,   302,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   303,
     304,     0,     0,     0,   305,     0,     0,     0,     0,     0,
     223,   306,     0,   307,   308,   309,   310,   311,   312,   313,
     314,   315,   316,     0,     0,     0,   224,   317,   318,   319,
       0,   320,   321,   322,   323,   324,   325,   326,     0,   327,
     328,     0,     0,   329,   226,   330,   227,   869,   332,   333,
     334,   335,   336,     0,   337,   229,   230,   338,   339,   340,
     341,     0,   342,   343,   344,   345,   346,   234,   347,   348,
     349,   350,   351,   352,   353,   354,   355,   356,   357,   358,
     359,     0,   235,     0,   360,   361,   362,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,     0,     0,   363,
       0,     0,     0,     0,   364,     0,     0,   365,     0,     0,
     366,   367,     0,   368,   369,    85,    86,    87,    88,    89,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    90,     0,     0,   273,    92,    93,     0,
      94,    95,    96,   274,     0,     0,    97,     0,    98,     0,
      99,   100,   101,   275,   102,     0,     0,   103,     0,   104,
     276,   277,   105,     0,     0,   106,   107,   108,   109,   110,
     111,     0,     0,   112,   113,   114,   278,   115,   279,   116,
     280,     0,     0,   118,   119,     0,     0,     0,     0,   120,
     121,   122,   123,   281,   124,   125,   126,     0,     0,   127,
       0,   282,   128,   129,     0,   130,     0,     0,   131,     0,
     283,     0,   132,     0,     0,   133,     0,     0,   134,   135,
       0,   136,   137,     0,     0,   138,   139,     0,   140,   141,
     142,   143,   284,     0,     0,     0,   144,     0,   145,     0,
     146,   285,     0,     0,   147,   286,     0,   148,   149,     0,
       0,   150,     0,     0,   151,     0,     0,   152,   153,     0,
       0,     0,     0,   287,   154,     0,     0,     0,   155,   288,
     156,   289,     0,     0,   157,   158,   159,   160,   161,   162,
     163,     0,   164,   165,   290,   166,   167,   168,   169,   170,
     171,   172,   173,   174,   175,     0,   176,   177,   291,   178,
     292,   293,   179,     0,   180,     0,     0,     0,     0,     0,
       0,     0,   181,   182,     0,     0,     0,   183,   184,   185,
     186,   187,   188,   189,   190,     0,   294,     0,     0,   191,
       0,   192,     0,   193,   194,     0,     0,   195,   196,   197,
       0,   198,   199,   200,     0,     0,   201,     0,   202,     0,
       0,   203,     0,   295,     0,     0,   204,   205,   296,   297,
     298,   299,     0,     0,   206,   207,     0,     0,     0,   208,
       0,     0,     0,   209,     0,     0,     0,   210,     0,   211,
       0,     0,   300,   212,   301,   213,   302,     0,     0,   215,
     216,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   217,     0,   218,     0,   219,   220,   303,   304,     0,
       0,     0,   305,     0,     0,     0,     0,     0,   223,   306,
       0,   307,   308,   309,   310,   311,   312,   313,   314,   315,
     316,     0,     0,     0,   224,   317,   318,   319,     0,   320,
     321,   322,   323,   324,   325,   326,     0,   327,   328,     0,
       0,   329,   226,   330,   227,  1394,   332,   333,   334,   335,
     336,     0,   337,   229,   230,   338,   339,   340,   341,     0,
     342,   343,   344,   345,   346,   234,   347,   348,   349,   350,
     351,   352,   353,   354,   355,   356,   357,   358,   359,     0,
     235,     0,   360,   361,   362,   237,     0,     0,   238,     0,
     239,     0,   240,   241,   242,     0,     0,   363,     0,     0,
       0,     0,   364,     0,     0,   365,     0,     0,   366,   367,
       0,   368,   369,    85,    86,    87,    88,    89,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    90,     0,     0,   273,    92,    93,     0,    94,    95,
      96,   274,     0,     0,    97,     0,    98,     0,    99,   100,
     101,   275,   102,     0,     0,   103,     0,   104,   276,   277,
     105,     0,     0,   106,   107,   108,   109,   110,   111,     0,
       0,   112,   113,   114,   278,   115,   279,   116,   280,     0,
       0,   118,   119,     0,     0,     0,     0,   120,   121,   122,
     123,   281,   124,   125,   126,     0,     0,   127,     0,   282,
     128,   129,     0,   130,     0,     0,   131,     0,   283,     0,
     132,     0,     0,   133,     0,     0,   134,   135,     0,   136,
     137,     0,     0,   138,   139,     0,   140,   141,   142,   143,
     284,     0,     0,     0,   144,     0,   145,     0,   146,   285,
       0,     0,   147,   286,     0,   148,   149,     0,     0,   150,
       0,     0,   151,     0,     0,   152,   153,     0,     0,     0,
       0,   287,   154,     0,     0,     0,   155,   288,   156,   289,
       0,     0,   157,   158,   159,   160,   161,   162,   163,     0,
     164,   165,   290,   166,   167,   168,   169,   170,   171,   172,
     173,   174,   175,     0,   176,   177,   291,   178,   292,   293,
     179,     0,   180,     0,     0,     0,     0,     0,     0,     0,
     181,   182,     0,     0,     0,   183,   184,   185,   186,   187,
     188,   189,   190,     0,   294,     0,     0,   191,     0,   192,
       0,   193,   194,     0,     0,   195,   196,   197,     0,   198,
     199,   200,     0,     0,   201,     0,   202,     0,     0,   203,
       0,   295,     0,     0,   204,   205,   296,   297,   298,   299,
       0,     0,   206,   207,     0,     0,     0,   208,     0,     0,
       0,   209,     0,     0,     0,   210,     0,   211,     0,     0,
     300,   212,   301,   213,   302,     0,     0,   215,   216,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   217,
       0,   218,     0,   219,   220,   303,   304,     0,     0,     0,
     305,     0,     0,     0,     0,     0,   223,   306,     0,   307,
     308,   309,   310,   311,   312,   313,   314,   315,   316,     0,
       0,     0,   224,   317,   318,   319,     0,   320,   321,   322,
     323,   324,   325,   326,     0,   327,   328,     0,     0,   329,
     226,   330,   227,  1396,   332,   333,   334,   335,   336,     0,
     337,   229,   230,   338,   339,   340,   341,     0,   342,   343,
     344,   345,   346,   234,   347,   348,   349,   350,   351,   352,
     353,   354,   355,   356,   357,   358,   359,     0,   235,     0,
     360,   361,   362,   237,     0,     0,   238,     0,   239,     0,
     240,   241,   242,     0,     0,   363,     0,     0,     0,     0,
     364,     0,     0,   365,     0,     0,   366,   367,     0,   368,
     369,    85,    86,    87,    88,    89,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    90,
       0,     0,   273,    92,    93,     0,    94,    95,    96,   274,
       0,     0,    97,     0,    98,     0,    99,   100,   101,   275,
     102,     0,     0,   103,     0,   104,   276,   277,   105,     0,
       0,   106,   107,   108,   109,   110,   111,     0,     0,   112,
     113,   114,   278,   115,   279,   116,   280,     0,     0,   118,
     119,     0,     0,     0,     0,   120,   121,   122,   123,   281,
     124,   125,   126,     0,     0,   127,     0,   282,   128,   129,
       0,   130,     0,     0,   131,     0,   283,     0,   132,     0,
       0,   133,     0,     0,   134,   135,     0,   136,   137,     0,
       0,   138,   139,     0,   140,   141,   142,   143,   284,     0,
       0,     0,   144,     0,   145,     0,   146,   285,     0,     0,
     147,   286,     0,   148,   149,     0,     0,   150,     0,     0,
     151,     0,     0,   152,   153,     0,     0,     0,     0,   287,
     154,     0,     0,     0,   155,   288,   156,   289,     0,     0,
     157,   158,   159,   160,   161,   162,   163,     0,   164,   165,
     290,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,     0,   176,   177,   291,   178,   292,   293,   179,     0,
     180,     0,     0,     0,     0,     0,     0,     0,   181,   182,
       0,     0,     0,   183,   184,   185,   186,   187,   188,   189,
     190,     0,   294,     0,     0,   191,     0,   192,     0,   193,
     194,     0,     0,   195,   196,   197,     0,   198,   199,   200,
       0,     0,   201,     0,   202,     0,     0,   203,     0,   295,
       0,     0,   204,   205,   296,   297,   298,   299,     0,     0,
     206,   207,     0,     0,     0,   208,     0,     0,     0,   209,
       0,     0,     0,   210,     0,   211,     0,     0,   300,   212,
     301,   213,   302,     0,     0,   215,   216,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   217,     0,   218,
       0,   219,   220,   303,   304,     0,     0,     0,   305,     0,
       0,     0,     0,     0,   223,   306,     0,   307,   308,   309,
     310,   311,   312,   313,   314,   315,   316,     0,     0,     0,
     224,   317,   318,   319,     0,   320,   321,   322,   323,   324,
     325,   326,     0,   327,   328,     0,     0,   329,   226,   330,
     227,  1446,   332,   333,   334,   335,   336,     0,   337,   229,
     230,   338,   339,   340,   341,     0,   342,   343,   344,   345,
     346,   234,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,     0,   235,     0,   360,   361,
     362,   237,     0,     0,   238,     0,   239,     0,   240,   241,
     242,     0,     0,   363,     0,     0,     0,     0,   364,     0,
       0,   365,     0,     0,   366,   367,     0,   368,   369,    85,
      86,    87,    88,    89,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    90,     0,     0,
     273,    92,    93,     0,    94,    95,    96,   274,     0,     0,
      97,     0,    98,     0,    99,   100,   101,   275,   102,     0,
       0,   103,     0,   104,   276,   277,   105,     0,     0,   106,
     107,   108,   109,   110,   111,     0,     0,   112,   113,   114,
     278,   115,   279,   116,   280,     0,     0,   118,   119,     0,
       0,     0,     0,   120,   121,   122,   123,   281,   124,   125,
     126,     0,     0,   127,     0,   282,   128,   129,     0,   130,
       0,     0,   131,     0,   283,     0,   132,     0,     0,   133,
       0,     0,   134,   135,     0,   136,   137,     0,     0,   138,
     139,     0,   140,   141,   142,   143,   284,     0,     0,     0,
     144,     0,   145,     0,   146,   285,     0,     0,   147,   286,
       0,   148,   149,     0,     0,   150,     0,     0,   151,     0,
       0,   152,   153,     0,     0,     0,     0,   287,   154,     0,
       0,     0,   155,   288,   156,   289,     0,     0,   157,   158,
     159,   160,   161,   162,   163,     0,   164,   165,   290,   166,
     167,   168,   169,   170,   171,   172,   173,   174,   175,     0,
     176,   177,   291,   178,   292,   293,   179,     0,   180,     0,
       0,     0,     0,     0,     0,     0,   181,   182,     0,     0,
       0,   183,   184,   185,   186,   187,   188,   189,   190,     0,
     294,     0,     0,   191,     0,   192,     0,   193,   194,     0,
       0,   195,   196,   197,     0,   198,   199,   200,     0,     0,
     201,     0,   202,     0,     0,   203,     0,   295,     0,     0,
     204,   205,   296,   297,   298,   299,     0,     0,   206,   207,
       0,     0,     0,   208,     0,     0,     0,   209,     0,     0,
       0,   210,     0,   211,     0,     0,   300,   212,   301,   213,
     302,     0,     0,   215,   216,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   217,     0,   218,     0,   219,
     220,   303,   304,     0,     0,     0,   305,     0,     0,     0,
       0,     0,   223,   306,     0,   307,   308,   309,   310,   311,
     312,   313,   314,   315,   316,     0,     0,     0,   224,   317,
     318,   319,     0,   320,   321,   322,   323,   324,   325,   326,
       0,   327,   328,     0,     0,   329,   226,   330,   227,  1448,
     332,   333,   334,   335,   336,     0,   337,   229,   230,   338,
     339,   340,   341,     0,   342,   343,   344,   345,   346,   234,
     347,   348,   349,   350,   351,   352,   353,   354,   355,   356,
     357,   358,   359,     0,   235,     0,   360,   361,   362,   237,
       0,     0,   238,     0,   239,     0,   240,   241,   242,     0,
       0,   363,     0,     0,     0,     0,   364,     0,     0,   365,
       0,     0,   366,   367,     0,   368,   369,    85,    86,    87,
      88,    89,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,    90,     0,     0,    91,    92,
      93,     0,    94,    95,    96,     0,     0,     0,    97,     0,
      98,     0,    99,   100,   101,     0,   102,     0,     0,   103,
       0,   104,     0,     0,   105,     0,     0,   106,   107,   108,
     109,   110,   111,  1521,     0,   112,   113,   114,     0,   115,
       0,   116,   117,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,     0,   124,   125,   126,     0,
       0,   127,     0,     0,   128,   129,     0,   130,     0,     0,
     131,  1536,     0,     0,   132,     0,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,     0,     0,     0,     0,   144,  1537,
     145,     0,   146,     0,     0,     0,   147,     0,     0,   148,
     149,     0,  1538,   150,     0,     0,   151,     0,     0,   152,
     153,     0,     0,  1539,     0,     0,   154,     0,     0,     0,
     155,     0,   156,     0,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,     0,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
       0,   178,     0,     0,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,     0,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,     0,     0,     0,   204,   205,
       0,     0,     0,     0,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,     0,   212,     0,   213,   214,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   221,
     222,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     223,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   224,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   225,   226,     0,   227,     0,     0,     0,
       0,     0,     0,     0,   228,   229,   230,   231,     0,   232,
       0,     0,     0,     0,     0,     0,   233,   234,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   235,     0,   236,     0,     0,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,    85,    86,    87,
      88,    89,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  1583,    90,     0,     0,    91,    92,
      93,     0,    94,    95,    96,     0,     0,     0,    97,     0,
      98,     0,    99,   100,   101,     0,   102,     0,     0,   103,
       0,   104,     0,     0,   105,     0,     0,   106,   107,   108,
     109,   110,   111,     0,     0,   112,   113,   114,     0,   115,
       0,   116,   117,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,     0,   124,   125,   126,     0,
       0,   127,     0,     0,   128,   129,     0,   130,     0,     0,
     131,  1536,     0,     0,   132,     0,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,     0,     0,     0,     0,   144,  1537,
     145,     0,   146,     0,     0,     0,   147,     0,     0,   148,
     149,     0,  1538,   150,     0,     0,   151,     0,     0,   152,
     153,     0,     0,  1539,     0,     0,   154,     0,     0,     0,
     155,     0,   156,     0,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,     0,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
       0,   178,     0,     0,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,     0,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,     0,     0,     0,   204,   205,
       0,     0,     0,     0,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,     0,   212,     0,   213,   214,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   221,
     222,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     223,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   224,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   225,   226,     0,   227,     0,     0,     0,
       0,     0,     0,     0,   228,   229,   230,   231,     0,   232,
       0,     0,     0,     0,     0,     0,   233,   234,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   235,     0,   236,     0,     0,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,    85,    86,    87,
      88,    89,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  1583,    90,     0,     0,    91,    92,
      93,     0,    94,    95,    96,     0,     0,     0,    97,     0,
      98,     0,    99,   100,   101,     0,   102,     0,     0,   103,
       0,   104,     0,     0,   105,     0,     0,   106,   107,   108,
     109,   110,   111,    23,     0,   112,   113,   114,     0,   115,
       0,   116,   117,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,     0,   124,   125,   126,     0,
       0,   127,     0,     0,   128,   129,     0,   130,     0,     0,
     131,     0,     0,     0,   132,     0,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,     0,     0,     0,     0,   144,     0,
     145,     0,   146,     0,     0,     0,   147,     0,     0,   148,
     149,     0,     0,   150,     0,     0,   151,     0,     0,   152,
     153,     0,     0,     0,     0,     0,   154,     0,     0,     0,
     155,     0,   156,     0,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,     0,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
       0,   178,     0,     0,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,     0,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,     0,     0,     0,   204,   205,
       0,     0,     0,     0,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,     0,   212,     0,   213,   214,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   221,
     222,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     223,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   224,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   225,   226,     0,   227,     0,     0,     0,
       0,     0,     0,     0,   228,   229,   230,   231,     0,   232,
       0,     0,     0,     0,     0,     0,   233,   234,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   235,     0,   236,     0,     0,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,    85,    86,    87,
      88,    89,     0,     0,     0,     0,     0,    42,     0,     0,
       0,     0,     0,     0,   243,    90,     0,     0,    91,    92,
      93,     0,    94,    95,    96,     0,     0,     0,    97,     0,
      98,     0,    99,   100,   101,     0,   102,     0,     0,   103,
       0,   104,     0,     0,   105,     0,     0,   106,   107,   108,
     109,   110,   111,  1521,     0,   112,   113,   114,     0,   115,
       0,   116,   117,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,     0,   124,   125,   126,     0,
       0,   127,     0,     0,   128,   129,     0,   130,     0,     0,
     131,     0,     0,     0,   132,     0,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,     0,     0,     0,     0,   144,     0,
     145,     0,   146,     0,     0,     0,   147,     0,     0,   148,
     149,     0,     0,   150,     0,     0,   151,     0,     0,   152,
     153,     0,     0,     0,     0,     0,   154,     0,     0,     0,
     155,     0,   156,     0,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,     0,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
       0,   178,     0,     0,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,     0,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,     0,     0,     0,   204,   205,
       0,     0,     0,     0,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,     0,   212,     0,   213,   214,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   221,
     222,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     223,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   224,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   225,   226,     0,   227,     0,     0,     0,
       0,     0,     0,     0,   228,   229,   230,   231,     0,   232,
       0,     0,     0,     0,     0,     0,   233,   234,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   235,     0,   236,     0,     0,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,    85,    86,    87,
      88,    89,     0,     0,     0,     0,     0,     0,  1764,     0,
       0,     0,     0,     0,   369,    90,     0,     0,    91,    92,
      93,     0,    94,    95,    96,     0,     0,     0,    97,     0,
      98,     0,    99,   100,   101,     0,   102,     0,     0,   103,
       0,   104,     0,     0,   105,     0,     0,   106,   107,   108,
     109,   110,   111,     0,     0,   112,   113,   114,     0,   115,
       0,   116,   117,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,     0,   124,   125,   126,     0,
       0,   127,     0,     0,   128,   129,     0,   130,     0,     0,
     131,     0,     0,     0,   132,     0,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,     0,     0,     0,     0,   144,     0,
     145,     0,   146,     0,     0,     0,   147,     0,     0,   148,
     149,     0,     0,   150,     0,     0,   151,   946,     0,   152,
     153,     0,     0,     0,     0,     0,   154,     0,     0,     0,
     155,     0,   156,     0,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,     0,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
       0,   178,     0,     0,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,     0,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,     0,     0,     0,   204,   205,
       0,     0,     0,     0,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,     0,   212,     0,   213,   214,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   221,
     222,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     223,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   224,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   225,   226,     0,   227,     0,     0,     0,
       0,     0,     0,     0,   228,   229,   230,   231,     0,   232,
       0,     0,     0,     0,     0,     0,   233,   234,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   235,     0,   236,     0,     0,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,    85,    86,    87,
      88,    89,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   243,    90,     0,     0,    91,    92,
      93,     0,    94,    95,    96,     0,     0,     0,    97,     0,
      98,     0,    99,   100,   101,     0,   102,     0,     0,   103,
       0,   104,     0,     0,   105,     0,     0,   106,   107,   108,
     109,   110,   111,     0,     0,   112,   113,   114,     0,   115,
       0,   116,   117,     0,     0,   118,   119,     0,     0,     0,
       0,   120,   121,   122,   123,     0,   124,   125,   126,     0,
       0,   127,     0,     0,   128,   129,     0,   130,     0,     0,
     131,     0,     0,     0,   132,     0,     0,   133,     0,     0,
     134,   135,     0,   136,   137,     0,     0,   138,   139,     0,
     140,   141,   142,   143,     0,     0,     0,     0,   144,     0,
     145,     0,   146,     0,     0,     0,   147,     0,     0,   148,
     149,     0,     0,   150,     0,     0,   151,     0,     0,   152,
     153,     0,     0,     0,     0,     0,   154,     0,     0,     0,
     155,     0,   156,     0,     0,     0,   157,   158,   159,   160,
     161,   162,   163,     0,   164,   165,     0,   166,   167,   168,
     169,   170,   171,   172,   173,   174,   175,     0,   176,   177,
       0,   178,     0,     0,   179,     0,   180,     0,     0,     0,
       0,     0,     0,     0,   181,   182,     0,     0,     0,   183,
     184,   185,   186,   187,   188,   189,   190,     0,     0,     0,
       0,   191,     0,   192,     0,   193,   194,     0,     0,   195,
     196,   197,     0,   198,   199,   200,     0,     0,   201,     0,
     202,     0,     0,   203,     0,     0,     0,     0,   204,   205,
       0,     0,     0,     0,     0,     0,   206,   207,     0,     0,
       0,   208,     0,     0,     0,   209,     0,     0,     0,   210,
       0,   211,     0,     0,     0,   212,     0,   213,   214,     0,
       0,   215,   216,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   217,     0,   218,     0,   219,   220,   221,
     222,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     223,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   224,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   225,   226,     0,   227,     0,     0,     0,
       0,     0,     0,     0,   228,   229,   230,   231,     0,   232,
       0,     0,     0,     0,     0,     0,   233,   234,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   235,     0,   236,     0,     0,   237,     0,     0,
     238,     0,   239,     0,   240,   241,   242,     0,     0,     0,
       0,  1225,    85,    86,    87,    88,    89,     0,     0,     0,
       0,     0,     0,     0,   243,     0,     0,     0,     0,     0,
      90,     0,     0,    91,    92,    93,     0,    94,    95,    96,
       0,     0,     0,    97,     0,    98,     0,    99,   100,   101,
       0,   102,     0,     0,   103,     0,   104,     0,     0,   105,
       0,     0,   106,   107,   108,   109,   110,   111,     0,     0,
     112,   113,   114,     0,   115,     0,   116,   117,     0,     0,
     118,   119,     0,     0,     0,     0,   120,   121,   122,   123,
       0,   124,   125,   126,     0,     0,   127,     0,     0,   128,
     129,     0,   130,     0,     0,   131,     0,     0,     0,   132,
       0,     0,   133,     0,     0,   134,   135,     0,   136,   137,
       0,     0,   138,   139,     0,   140,   141,   142,   143,     0,
       0,     0,     0,   144,     0,   145,     0,   146,     0,     0,
       0,   147,     0,     0,   148,   149,     0,     0,   150,     0,
       0,   151,     0,     0,   152,   153,     0,     0,     0,     0,
       0,   154,     0,     0,     0,   155,     0,   156,     0,     0,
       0,   157,   158,   159,   160,   161,   162,   163,     0,   164,
     165,     0,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,     0,   176,   177,     0,   178,     0,     0,   179,
       0,   180,     0,     0,     0,     0,     0,     0,     0,   181,
     182,     0,     0,     0,   183,   184,   185,   186,   187,   188,
     189,   190,     0,     0,     0,     0,   191,     0,   192,     0,
     193,   194,     0,     0,   195,   196,   197,     0,   198,   199,
     200,     0,     0,   201,     0,   202,     0,     0,   203,     0,
       0,     0,     0,   204,   205,     0,     0,     0,     0,     0,
       0,   206,   207,     0,     0,     0,   208,     0,     0,     0,
     209,     0,     0,     0,   210,     0,   211,     0,     0,     0,
     212,     0,   213,   214,     0,     0,   215,   216,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   217,     0,
     218,     0,   219,   220,   221,   222,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   223,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   224,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   225,   226,
       0,   227,     0,     0,     0,     0,     0,     0,     0,   228,
     229,   230,   231,     0,   232,     0,     0,     0,     0,     0,
       0,   233,   234,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   235,     0,   236,
       0,     0,   237,     0,     0,   238,     0,   239,     0,   240,
     241,   242,    85,    86,    87,    88,    89,     0,     0,     0,
       0,     0,  1582,     0,     0,     0,     0,     0,     0,  1583,
      90,     0,     0,    91,    92,    93,     0,    94,    95,    96,
       0,     0,     0,    97,     0,    98,     0,    99,   100,   101,
       0,   102,     0,     0,   103,     0,   104,     0,     0,   105,
       0,     0,   106,   107,   108,   109,   110,   111,     0,     0,
     112,   113,   114,     0,   115,     0,   116,   117,     0,     0,
     118,   119,     0,     0,     0,     0,   120,   121,   122,   123,
       0,   124,   125,   126,     0,     0,   127,     0,     0,   128,
     129,     0,   130,     0,     0,   131,     0,     0,     0,   132,
       0,     0,   133,     0,     0,   134,   135,     0,   136,   137,
       0,     0,   138,   139,     0,   140,   141,   142,   143,     0,
       0,     0,     0,   144,     0,   145,     0,   146,     0,     0,
       0,   147,     0,     0,   148,   149,     0,     0,   150,     0,
       0,   151,     0,     0,   152,   153,     0,     0,     0,     0,
       0,   154,     0,     0,     0,   155,     0,   156,     0,     0,
       0,   157,   158,   159,   160,   161,   162,   163,     0,   164,
     165,     0,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,     0,   176,   177,     0,   178,     0,     0,   179,
       0,   180,     0,     0,     0,     0,     0,     0,     0,   181,
     182,     0,     0,     0,   183,   184,   185,   186,   187,   188,
     189,   190,     0,     0,     0,     0,   191,     0,   192,     0,
     193,   194,     0,     0,   195,   196,   197,     0,   198,   199,
     200,     0,     0,   201,     0,   202,     0,     0,   203,     0,
       0,     0,     0,   204,   205,     0,     0,     0,     0,     0,
       0,   206,   207,     0,     0,     0,   208,     0,     0,     0,
     209,     0,     0,     0,   210,     0,   211,     0,     0,     0,
     212,     0,   213,   214,     0,     0,   215,   216,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   217,     0,
     218,     0,   219,   220,   221,   222,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   223,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   224,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   225,   226,
       0,   227,     0,     0,     0,     0,     0,     0,     0,   228,
     229,   230,   231,     0,   232,     0,     0,     0,     0,     0,
       0,   233,   234,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   235,     0,   236,
       0,     0,   237,     0,     0,   238,     0,   239,     0,   240,
     241,   242,    85,    86,    87,    88,    89,     0,     0,     0,
       0,     0,     0,  2394,     0,     0,     0,     0,     0,   369,
      90,     0,     0,    91,    92,    93,     0,    94,    95,    96,
       0,     0,     0,    97,     0,    98,     0,    99,   100,   101,
       0,   102,     0,     0,   103,     0,   104,     0,     0,   105,
       0,     0,   106,   107,   108,   109,   110,   111,     0,     0,
     112,   113,   114,     0,   115,     0,   116,   117,     0,     0,
     118,   119,     0,     0,     0,     0,   120,   121,   122,   123,
       0,   124,   125,   126,     0,     0,   127,     0,     0,   128,
     129,     0,   130,     0,     0,   131,     0,     0,     0,   132,
       0,     0,   133,     0,     0,   134,   135,     0,   136,   137,
       0,     0,   138,   139,     0,   140,   141,   142,   143,     0,
       0,     0,     0,   144,     0,   145,     0,   146,     0,     0,
       0,   147,     0,     0,   148,   149,     0,     0,   150,     0,
       0,   151,     0,     0,   152,   153,     0,     0,     0,     0,
       0,   154,     0,     0,     0,   155,     0,   156,     0,     0,
       0,   157,   158,   159,   160,   161,   162,   163,     0,   164,
     165,     0,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,     0,   176,   177,     0,   178,     0,     0,   179,
       0,   180,     0,     0,     0,     0,     0,     0,     0,   181,
     182,     0,     0,     0,   183,   184,   185,   186,   187,   188,
     189,   190,     0,     0,     0,     0,   191,     0,   192,     0,
     193,   194,     0,     0,   195,   196,   197,     0,   198,   199,
     200,     0,     0,   201,     0,   202,     0,     0,   203,     0,
       0,     0,     0,   204,   205,     0,     0,     0,     0,     0,
       0,   206,   207,     0,     0,     0,   208,     0,     0,     0,
     209,     0,     0,     0,   210,     0,   211,     0,     0,     0,
     212,     0,   213,   214,     0,     0,   215,   216,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   217,     0,
     218,     0,   219,   220,   221,   222,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   223,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   224,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   225,   226,
       0,   227,     0,     0,     0,     0,     0,     0,     0,   228,
     229,   230,   231,     0,   232,     0,     0,     0,     0,     0,
       0,   233,   234,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   235,     0,   236,
       0,     0,   237,     0,     0,   238,     0,   239,     0,   240,
     241,   242,    85,    86,    87,    88,    89,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   243,
      90,     0,     0,    91,    92,    93,     0,    94,    95,    96,
       0,     0,     0,    97,     0,    98,     0,    99,   100,   101,
       0,   102,     0,     0,   103,     0,   104,     0,     0,   105,
       0,     0,   106,   107,   108,   109,   110,   111,     0,     0,
     112,   113,   114,     0,   115,     0,   116,   117,     0,     0,
     118,   119,     0,     0,     0,     0,   120,   121,   122,   123,
       0,   124,   125,   126,     0,     0,   127,     0,     0,   128,
     129,     0,   130,     0,     0,   131,     0,     0,     0,   132,
       0,     0,   133,     0,     0,   134,   135,     0,   136,   137,
       0,     0,   138,   139,     0,   140,   141,   142,   143,     0,
       0,     0,     0,   144,     0,   145,     0,   146,     0,     0,
       0,   147,     0,     0,   148,   149,     0,     0,   150,     0,
       0,   151,     0,     0,   152,   153,     0,     0,     0,     0,
       0,   154,     0,     0,     0,   155,     0,   156,     0,     0,
       0,   157,   158,   159,   160,   161,   162,   163,     0,   164,
     165,     0,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,     0,   176,   177,     0,   178,     0,     0,   179,
       0,   180,     0,     0,     0,     0,     0,     0,     0,   181,
     182,     0,     0,     0,   183,   184,   185,   186,   187,   188,
     189,   190,     0,     0,     0,     0,   191,     0,   192,     0,
     193,   194,     0,     0,   195,   196,   197,     0,   198,   199,
     200,     0,     0,   201,     0,   202,     0,     0,   203,     0,
       0,     0,     0,   204,   205,     0,     0,     0,     0,     0,
       0,   206,   207,     0,     0,     0,   208,     0,     0,     0,
     209,     0,     0,     0,   210,     0,   211,     0,     0,     0,
     212,     0,   213,   214,     0,     0,   215,   216,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   217,     0,
     218,     0,   219,   220,   221,   222,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   223,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   224,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   225,   226,
       0,   227,     0,     0,     0,     0,     0,     0,     0,   228,
     229,   230,   231,     0,   232,     0,     0,     0,     0,     0,
       0,   233,   234,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   235,     0,   236,
       0,     0,   237,     0,     0,   238,     0,   239,     0,   240,
     241,   242,    85,    86,    87,    88,    89,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   369,
      90,     0,     0,    91,    92,    93,     0,    94,    95,    96,
       0,     0,     0,    97,     0,    98,     0,    99,   100,   101,
       0,   102,     0,     0,   103,     0,   104,     0,     0,   105,
       0,     0,   106,   107,   108,   109,   110,   111,     0,     0,
     112,   113,   114,     0,   115,     0,   116,   117,     0,     0,
     118,   119,     0,     0,     0,     0,   120,   121,   122,   123,
       0,   124,   125,   126,     0,     0,   127,     0,     0,   128,
     129,     0,   130,     0,     0,   131,     0,     0,     0,   132,
       0,     0,   133,     0,     0,   134,   135,     0,   136,   137,
       0,     0,   138,   139,     0,   140,   141,   142,   143,     0,
       0,     0,     0,   144,     0,   145,     0,   146,     0,     0,
       0,   147,     0,     0,   148,   149,     0,     0,   150,     0,
       0,   151,     0,     0,   152,   153,     0,     0,     0,     0,
       0,   154,     0,     0,     0,   155,     0,   156,     0,     0,
       0,   157,   158,   159,   160,   161,   162,   163,     0,   164,
     165,     0,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,     0,   176,   177,     0,   178,     0,     0,   179,
       0,   180,     0,     0,     0,     0,     0,     0,     0,   181,
     182,     0,     0,     0,   183,   184,   185,   186,   187,   188,
     189,   190,     0,     0,     0,     0,   191,     0,   192,     0,
     193,   194,     0,     0,   195,   196,   197,     0,   198,   199,
     200,     0,     0,   201,     0,   202,     0,     0,   203,     0,
       0,     0,     0,   204,   205,     0,     0,     0,     0,     0,
       0,   206,   207,     0,     0,     0,   208,     0,     0,     0,
     209,     0,     0,     0,   210,     0,   211,     0,     0,     0,
     212,     0,   213,   214,     0,     0,   215,   216,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   217,     0,
     218,     0,   219,   220,   221,   222,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   223,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   224,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   225,   226,
       0,   227,     0,     0,     0,     0,     0,     0,     0,   228,
     229,   230,   231,     0,   232,     0,     0,     0,     0,     0,
       0,   233,   234,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   235,     0,   236,
       0,     0,   237,     0,     0,   238,     0,   239,     0,   240,
     241,   242,    85,    86,    87,    88,    89,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  1583,
      90,     0,     0,    91,    92,    93,     0,    94,    95,    96,
       0,     0,     0,    97,     0,    98,     0,    99,   100,   101,
       0,   102,     0,     0,   103,     0,   104,     0,     0,   105,
       0,     0,   106,   107,   108,   109,   110,   111,     0,     0,
     112,   113,   114,     0,   115,     0,   116,   117,     0,     0,
     118,   119,     0,     0,     0,     0,   120,   121,   122,   123,
       0,   124,   125,   126,     0,     0,   127,     0,     0,   128,
     129,     0,   130,     0,     0,   131,     0,     0,     0,   132,
       0,     0,   133,     0,     0,   134,   135,     0,   136,   137,
       0,     0,   138,   139,     0,   140,   141,   142,   143,     0,
       0,     0,     0,   144,     0,   145,     0,   146,     0,     0,
       0,   147,     0,     0,   148,   149,     0,     0,   150,     0,
       0,   151,     0,     0,   152,   153,     0,     0,     0,     0,
       0,   154,   555,     0,     0,   155,     0,   156,     0,     0,
       0,   157,   158,   159,   160,   161,   162,   163,     0,   164,
     165,     0,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,     0,   176,   177,     0,   178,     0,     0,   179,
       0,   180,     0,     0,     0,     0,     0,     0,     0,   181,
     182,     0,     0,     0,   183,   184,   185,   186,   187,   188,
     189,   190,     0,     0,     0,     0,   191,     0,   192,     0,
     193,   194,     0,     0,   195,   196,   197,     0,   198,   199,
     200,     0,     0,   201,     0,   202,     0,     0,   203,     0,
     556,     0,     0,   204,   205,     0,     0,     0,     0,     0,
       0,   206,   207,     0,     0,     0,   208,     0,     0,     0,
     209,     0,     0,     0,   210,     0,   211,     0,     0,     0,
     212,     0,   213,   214,     0,     0,   215,   216,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   217,     0,
     218,     0,   219,   220,   221,   222,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   223,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   224,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   225,   226,
       0,   227,     0,     0,     0,     0,     0,     0,     0,   228,
     229,   230,   231,     0,   232,     0,     0,     0,     0,     0,
       0,   233,   234,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   235,     0,   236,
       0,     0,   237,     0,     0,   238,     0,   239,     0,   240,
     241,   242,    85,    86,    87,    88,    89,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   557,     0,
      90,     0,     0,    91,    92,    93,     0,    94,    95,    96,
       0,     0,     0,    97,     0,    98,     0,    99,   100,   101,
       0,   102,     0,     0,   103,     0,   104,     0,     0,   105,
       0,     0,   106,   107,   108,   109,   110,   111,     0,     0,
     112,   113,   114,     0,   115,     0,   116,   117,     0,     0,
     118,   119,     0,     0,     0,     0,   120,   121,   122,   123,
       0,   124,   125,   126,     0,     0,   127,     0,     0,   128,
     129,     0,   130,     0,     0,   131,     0,     0,     0,   132,
       0,     0,   133,     0,     0,   134,   135,     0,   136,   137,
       0,     0,   138,   139,     0,   140,   141,   142,   143,     0,
       0,     0,     0,   144,     0,   145,     0,   146,     0,     0,
       0,   147,     0,     0,   148,   149,     0,     0,   150,     0,
       0,   151,     0,     0,   152,   153,     0,     0,     0,     0,
       0,   154,   555,     0,     0,   155,     0,   156,     0,     0,
       0,   157,   158,   159,   160,   161,   162,   163,     0,   164,
     165,     0,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,     0,   176,   177,     0,   178,     0,     0,   179,
       0,   180,     0,     0,     0,     0,     0,     0,     0,   181,
     182,     0,     0,     0,   183,   184,   185,   186,   187,   188,
     189,   190,     0,     0,     0,     0,   191,     0,   192,     0,
     193,   194,     0,     0,   195,   196,   197,     0,   198,   199,
     200,     0,     0,   201,     0,   202,     0,     0,   203,     0,
     556,     0,     0,   204,   205,     0,     0,     0,     0,     0,
       0,   206,   207,     0,     0,     0,   208,     0,     0,     0,
     209,     0,     0,     0,   210,     0,   211,     0,     0,     0,
     212,     0,   213,   214,     0,     0,   215,   216,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   217,     0,
     218,     0,   219,   220,   221,   222,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   223,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   224,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   225,   226,
       0,   227,     0,     0,     0,     0,     0,     0,     0,   228,
     229,   230,   231,     0,   232,     0,     0,     0,     0,     0,
       0,   233,   234,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   235,     0,   236,
       0,     0,   237,     0,     0,   238,     0,   239,     0,   240,
     241,   242,    85,    86,    87,    88,    89,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1518,     0,
      90,     0,     0,    91,    92,    93,     0,    94,    95,    96,
       0,     0,     0,    97,     0,    98,     0,    99,   100,   101,
       0,   102,     0,     0,   103,     0,   104,     0,     0,   105,
       0,     0,   106,   107,   108,   109,   110,   111,     0,     0,
     112,   113,   114,     0,   115,     0,   116,   117,     0,     0,
     118,   119,     0,     0,     0,     0,   120,   121,   122,   123,
       0,   124,   125,   126,     0,     0,   127,     0,     0,   128,
     129,     0,   130,     0,     0,   131,     0,     0,     0,   132,
       0,     0,   133,     0,     0,   134,   135,     0,   136,   137,
       0,     0,   138,   139,     0,   140,   141,   142,   143,     0,
       0,     0,     0,   144,     0,   145,     0,   146,     0,     0,
       0,   147,     0,     0,   148,   149,     0,     0,   150,     0,
       0,   151,     0,     0,   152,   153,     0,     0,     0,     0,
       0,   154,     0,     0,     0,   155,     0,   156,     0,     0,
       0,   157,   158,   159,   160,   161,   162,   163,     0,   164,
     165,     0,   166,   167,   168,   169,   170,   171,   172,   173,
     174,   175,     0,   176,   177,     0,   178,     0,     0,   179,
       0,   180,     0,     0,     0,     0,     0,     0,     0,   181,
     182,     0,     0,     0,   183,   184,   185,   186,   187,   188,
     189,   190,     0,     0,     0,     0,   191,     0,   192,     0,
     193,   194,     0,     0,   195,   196,   197,     0,   198,   199,
     200,     0,     0,   201,     0,   202,     0,     0,   203,     0,
       0,     0,     0,  1235,   205,     0,     0,     0,     0,     0,
       0,   206,   207,     0,     0,     0,   208,     0,     0,     0,
     209,     0,     0,     0,   210,     0,   211,     0,     0,  1236,
     212,     0,   213,   214,     0,     0,   215,   216,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,   217,     0,
     218,     0,   219,   220,   221,   222,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   223,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,     0,     0,     0,     0,
       0,   224,   561,   562,   563,   564,   565,   566,   567,   568,
     569,   570,     0,     0,     0,     0,     0,     0,   225,   226,
       0,   227,     0,     0,   571,     0,     0,     0,     0,   228,
     229,   230,   231,     0,  1237,     0,     0,     0,     0,     0,
       0,   233,   234,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   571,     0,     0,     0,     0,   235,     0,   236,
       0,     0,   237,     0,     0,   238,     0,   239,   571,   240,
     241,   242,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1238,     0,
       0,     0,     0,     0,   572,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   573,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,     0,     0,     0,     0,
       0,     0,   572,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   573,     0,     0,     0,   574,     0,   572,     0,
       0,     0,     0,     0,     0,   575,   576,     0,   573,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
       0,     0,     0,     0,   574,     0,   577,     0,     0,     0,
       0,   571,     0,   575,   576,     0,     0,     0,     0,     0,
     574,     0,     0,     0,     0,     0,     0,     0,     0,   575,
     576,     0,     0,     0,   577,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     577,     0,     0,     0,     0,   571,   578,     0,     0,     0,
       0,     0,   561,   562,   563,   564,   565,   566,   567,   568,
     569,   570,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   572,     0,     0,   578,     0,     0,     0,     0,     0,
       0,   573,     0,     0,     0,     0,     0,     0,   579,     0,
     578,     0,     0,     0,     0,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,     0,     0,     0,     0,
       0,     0,     0,   574,     0,   572,   579,     0,   571,     0,
       0,     0,   575,   576,     0,   573,     0,     0,     0,     0,
       0,     0,   579,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   577,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   574,     0,     0,
       0,   571,     0,     0,     0,     0,   575,   576,     0,     0,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,     0,  1029,  1030,     0,   577,   572,     0,
       0,     0,     0,   578,     0,     0,     0,     0,   573,     0,
       0,   580,   581,   582,   583,   584,   585,   586,     0,     0,
     587,     0,  1041,  1042,     0,     0,     0,   580,   581,   582,
     583,   584,   585,   586,     0,     0,   587,     0,  1043,  1044,
     574,   572,     0,     0,     0,   579,     0,   578,     0,   575,
     576,   573,   561,   562,   563,   564,   565,   566,   567,   568,
     569,   570,     0,     0,     0,     0,     0,     0,     0,     0,
     577,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   574,     0,     0,     0,     0,     0,   579,
       0,     0,   575,   576,     0,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,     0,     0,     0,     0,
       0,     0,     0,   577,     0,     0,     0,     0,   571,     0,
     578,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     580,   581,   582,   583,   584,   585,   586,     0,     0,   587,
       0,  1047,  1048,     0,     0,     0,     0,     0,     0,     0,
       0,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,   571,   579,   578,     0,     0,     0,  1102,     0,     0,
       0,     0,     0,     0,   580,   581,   582,   583,   584,   585,
     586,     0,     0,   587,     0,  1053,  1054,     0,   572,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   573,     0,
       0,     0,     0,     0,     0,   579,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   571,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
     574,   572,     0,     0,     0,     0,     0,     0,     0,   575,
     576,   573,     0,     0,     0,     0,     0,   580,   581,   582,
     583,   584,   585,   586,     0,     0,   587,     0,   833,  1058,
     577,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   574,     0,     0,     0,     0,     0,     0,
       0,     0,   575,   576,   571,     0,     0,   572,     0,     0,
     580,   581,   582,   583,   584,   585,   586,   573,     0,   587,
       0,  1099,  1100,   577,     0,     0,     0,     0,     0,     0,
     578,     0,     0,     0,     0,     0,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,     0,     0,     0,   574,
       0,     0,     0,     0,     0,     0,     0,     0,   575,   576,
       0,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,     0,   579,   578,   572,     0,     0,     0,     0,   577,
       0,     0,     0,     0,   573,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,     0,     0,     0,     0,
       0,     0,   571,     0,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,   579,   574,     0,     0,     0,
       0,     0,     0,     0,     0,   575,   576,   571,     0,   578,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   577,     0,     0,     0,
       0,   571,     0,     0,     0,     0,     0,   580,   581,   582,
     583,   584,   585,   586,     0,     0,   587,     0,     0,  1103,
     571,   579,   572,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   573,     0,     0,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,   578,   572,     0,     0,
     580,   581,   582,   583,   584,   585,   586,   573,     0,   587,
       0,  1119,  1120,     0,   574,     0,     0,     0,     0,     0,
       0,   572,     0,   575,   576,     0,     0,     0,     0,     0,
       0,   573,     0,     0,     0,     0,     0,     0,   579,   574,
     572,     0,     0,     0,   577,     0,     0,     0,   575,   576,
     573,   571,     0,     0,     0,     0,   580,   581,   582,   583,
     584,   585,   586,   574,     0,   587,     0,  1122,  1123,   577,
       0,     0,   575,   576,     0,     0,     0,     0,     0,     0,
       0,     0,   574,     0,     0,     0,     0,     0,     0,     0,
       0,   575,   576,   577,   578,     0,     0,     0,     0,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
       0,     0,   577,     0,     0,     0,     0,     0,     0,   578,
       0,   572,     0,   580,   581,   582,   583,   584,   585,   586,
       0,   573,   587,     0,  1657,  1658,   579,     0,     0,     0,
       0,     0,     0,   578,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   579,   578,   574,     0,   571,     0,     0,     0,     0,
       0,     0,   575,   576,     0,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,   579,     0,     0,     0,     0,
       0,     0,     0,   577,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   579,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   580,   581,   582,   583,   584,   585,   586,     0,     0,
     587,     0,  1660,  1661,     0,   572,     0,     0,     0,     0,
       0,   571,     0,   578,     0,   573,   580,   581,   582,   583,
     584,   585,   586,     0,     0,   587,     0,  1676,  1677,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
     580,   581,   582,   583,   584,   585,   586,   574,     0,   587,
       0,  2024,  2025,     0,     0,   579,   575,   576,     0,   580,
     581,   582,   583,   584,   585,   586,     0,     0,   587,     0,
    2260,  2261,     0,     0,     0,     0,     0,   577,     0,     0,
       0,   572,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   573,     0,     0,     0,   571,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   574,     0,     0,     0,   578,     0,     0,
       0,     0,   575,   576,     0,     0,     0,     0,     0,     0,
     580,   581,   582,   583,   584,   585,   586,     0,     0,   587,
       0,     0,  1007,   577,     0,     0,     0,     0,     0,     0,
       0,     0,   571,     0,     0,   572,     0,     0,     0,   579,
       0,     0,     0,     0,     0,   573,     0,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   578,     0,     0,     0,   574,     0,     0,
       0,     0,     0,     0,     0,     0,   575,   576,     0,     0,
     561,   562,   563,   564,   565,   566,   567,   568,   569,   570,
       0,     0,   572,     0,     0,     0,     0,   577,     0,     0,
       0,     0,   573,   571,     0,   579,     0,     0,     0,     0,
       0,     0,     0,     0,   580,   581,   582,   583,   584,   585,
     586,     0,     0,   587,     0,     0,  1012,     0,     0,     0,
       0,     0,     0,     0,   574,     0,     0,     0,     0,     0,
       0,     0,     0,   575,   576,     0,   571,   578,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   577,     0,     0,     0,     0,     0,
       0,     0,     0,   572,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   573,     0,     0,     0,     0,     0,   579,
     580,   581,   582,   583,   584,   585,   586,     0,     0,   587,
       0,     0,  1014,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,     0,   578,   574,   572,     0,     0,     0,
       0,     0,     0,     0,   575,   576,   573,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,     0,     0,     0,
       0,     0,     0,     0,     0,   577,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   579,     0,   574,     0,
       0,     0,     0,     0,     0,     0,     0,   575,   576,   571,
       0,     0,     0,     0,   580,   581,   582,   583,   584,   585,
     586,     0,     0,   587,     0,     0,  1015,     0,   577,     0,
       0,     0,     0,   571,     0,   578,     0,     0,     0,     0,
       0,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,     0,   579,   578,   572,
       0,   580,   581,   582,   583,   584,   585,   586,     0,   573,
     587,     0,     0,  1016,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   572,     0,     0,     0,   571,     0,     0,
       0,     0,     0,   573,     0,     0,     0,     0,     0,     0,
     579,   574,     0,     0,     0,     0,     0,     0,     0,     0,
     575,   576,   571,     0,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,   574,     0,     0,     0,     0,
       0,   577,     0,     0,   575,   576,     0,     0,     0,     0,
       0,     0,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,     0,     0,  1023,   577,     0,   572,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   573,     0,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
     571,   578,   572,     0,     0,   580,   581,   582,   583,   584,
     585,   586,   573,     0,   587,     0,     0,  1024,     0,   574,
       0,     0,     0,     0,     0,   578,     0,     0,   575,   576,
       0,     0,   561,   562,   563,   564,   565,   566,   567,   568,
     569,   570,     0,   579,   574,     0,     0,     0,     0,   577,
       0,     0,     0,   575,   576,   571,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   579,     0,     0,
     572,     0,     0,     0,   577,     0,     0,     0,     0,     0,
     573,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   571,   578,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   574,     0,     0,     0,     0,     0,     0,     0,
       0,   575,   576,     0,   578,   572,     0,     0,   580,   581,
     582,   583,   584,   585,   586,   573,     0,   587,     0,     0,
    1036,   579,   577,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,     0,     0,  1038,     0,   579,   574,   572,     0,
       0,     0,     0,     0,     0,     0,   575,   576,   573,     0,
     561,   562,   563,   564,   565,   566,   567,   568,   569,   570,
       0,     0,   578,     0,     0,     0,     0,   577,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     574,     0,     0,     0,     0,     0,     0,     0,     0,   575,
     576,     0,     0,     0,     0,     0,   580,   581,   582,   583,
     584,   585,   586,     0,   579,   587,     0,     0,  1039,     0,
     577,     0,     0,     0,     0,     0,   571,   578,     0,     0,
       0,   580,   581,   582,   583,   584,   585,   586,     0,     0,
     587,     0,     0,  1040,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,     0,     0,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,   579,
     578,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,     0,     0,     0,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,     0,   572,     0,     0,   580,
     581,   582,   583,   584,   585,   586,   573,     0,   587,     0,
     571,  1045,   579,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   571,     0,     0,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,   571,   574,     0,
       0,     0,     0,     0,     0,     0,     0,   575,   576,     0,
     571,     0,     0,     0,   580,   581,   582,   583,   584,   585,
     586,     0,     0,   587,     0,     0,  1046,     0,   577,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     572,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     573,     0,     0,   571,   572,     0,     0,   580,   581,   582,
     583,   584,   585,   586,   573,     0,   587,   572,     0,  1049,
       0,     0,     0,     0,     0,     0,     0,   573,   578,     0,
     572,     0,   574,     0,     0,     0,     0,     0,     0,     0,
     573,   575,   576,     0,     0,     0,   574,     0,     0,     0,
       0,     0,     0,     0,     0,   575,   576,     0,     0,   574,
       0,     0,   577,     0,     0,     0,     0,     0,   575,   576,
     579,     0,   574,   572,     0,     0,   577,     0,     0,     0,
       0,   575,   576,   573,     0,     0,     0,     0,     0,   577,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   577,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   578,     0,     0,   574,     0,     0,     0,     0,
       0,     0,     0,     0,   575,   576,   578,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,     0,     0,   578,
       0,     0,     0,     0,     0,   577,     0,     0,     0,     0,
       0,     0,   578,     0,   579,   580,   581,   582,   583,   584,
     585,   586,     0,     0,   587,     0,     0,  1051,   579,     0,
     561,   562,   563,   564,   565,   566,   567,   568,   569,   570,
       0,   579,     0,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,   571,   579,   578,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
       0,     0,     0,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,     0,     0,     0,   571,   579,     0,   580,
     581,   582,   583,   584,   585,   586,     0,     0,   587,   571,
       0,  1052,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,   572,     0,  1057,   580,   581,   582,   583,
     584,   585,   586,   573,   571,   587,     0,     0,  1061,   580,
     581,   582,   583,   584,   585,   586,     0,     0,   587,   571,
       0,  1062,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   574,   572,     0,     0,     0,
       0,     0,     0,     0,   575,   576,   573,     0,     0,   572,
       0,     0,   580,   581,   582,   583,   584,   585,   586,   573,
       0,   587,     0,     0,  1063,   577,     0,     0,     0,     0,
       0,     0,     0,     0,   572,     0,     0,     0,   574,     0,
       0,     0,     0,     0,   573,     0,     0,   575,   576,   572,
       0,   574,     0,     0,     0,     0,     0,     0,     0,   573,
     575,   576,     0,     0,     0,     0,     0,     0,   577,     0,
       0,     0,     0,     0,     0,   578,   574,     0,     0,     0,
       0,   577,     0,     0,     0,   575,   576,     0,     0,     0,
       0,   574,     0,     0,     0,     0,     0,     0,     0,     0,
     575,   576,     0,     0,     0,     0,   577,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   579,   578,     0,
       0,   577,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   578,     0,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   578,     0,     0,     0,
     579,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   578,     0,   579,     0,     0,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   579,   571,
       0,     0,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,     0,   579,  1064,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,     0,     0,     0,     0,
       0,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,     0,   571,     0,     0,   580,   581,   582,   583,   584,
     585,   586,     0,     0,   587,     0,     0,  1097,   580,   581,
     582,   583,   584,   585,   586,     0,     0,   587,     0,   572,
    1098,     0,     0,     0,     0,     0,     0,     0,     0,   573,
       0,   571,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,     0,     0,  1104,     0,   571,   580,   581,
     582,   583,   584,   585,   586,     0,     0,   587,     0,     0,
    1620,   574,   572,     0,     0,     0,     0,     0,     0,     0,
     575,   576,   573,     0,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,     0,     0,     0,     0,     0,
       0,   577,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   572,     0,     0,   574,     0,     0,     0,     0,     0,
       0,   573,     0,   575,   576,     0,     0,   572,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   573,     0,     0,
       0,     0,     0,     0,   577,     0,     0,     0,     0,     0,
     571,   578,     0,   574,     0,     0,     0,     0,     0,     0,
       0,     0,   575,   576,     0,     0,     0,     0,     0,   574,
       0,     0,     0,     0,     0,     0,     0,     0,   575,   576,
       0,     0,     0,   577,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   579,   578,     0,     0,     0,     0,   577,
       0,     0,     0,     0,     0,     0,     0,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
     572,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     573,     0,     0,   578,     0,     0,   579,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,     0,     0,   578,
       0,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,     0,   574,     0,     0,     0,     0,     0,     0,     0,
       0,   575,   576,     0,   571,   579,     0,     0,   580,   581,
     582,   583,   584,   585,   586,     0,     0,   587,     0,     0,
    1632,   579,   577,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   571,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,     0,     0,   571,     0,     0,
       0,   580,   581,   582,   583,   584,   585,   586,     0,     0,
     587,     0,     0,  1648,     0,     0,     0,     0,     0,     0,
       0,     0,   578,     0,   572,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   573,     0,     0,     0,     0,     0,
     580,   581,   582,   583,   584,   585,   586,     0,     0,   587,
     571,     0,  1654,   572,     0,     0,   580,   581,   582,   583,
     584,   585,   586,   573,   579,   587,   574,   572,  1671,     0,
       0,     0,     0,     0,     0,   575,   576,   573,     0,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
       0,     0,     0,     0,     0,   574,   577,     0,     0,     0,
       0,     0,     0,     0,   575,   576,     0,     0,     0,   574,
       0,     0,     0,     0,     0,     0,     0,     0,   575,   576,
     572,     0,     0,     0,     0,   577,     0,     0,     0,     0,
     573,     0,     0,     0,     0,     0,     0,     0,     0,   577,
       0,     0,     0,     0,     0,   571,   578,     0,     0,   580,
     581,   582,   583,   584,   585,   586,     0,     0,   587,     0,
       0,  1678,   574,     0,     0,     0,     0,     0,     0,     0,
       0,   575,   576,     0,     0,   578,     0,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,   579,   578,
       0,     0,   577,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,     0,     0,   572,     0,   579,     0,     0,
       0,     0,     0,     0,     0,   573,     0,     0,     0,     0,
       0,   579,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   578,  1674,   571,     0,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,     0,   574,     0,     0,
       0,     0,     0,     0,     0,     0,   575,   576,     0,   571,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,     0,   579,  2018,     0,   577,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,   571,  1675,   572,     0,   580,   581,   582,   583,
     584,   585,   586,     0,   573,   587,     0,   833,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   578,     0,   572,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   573,
       0,     0,     0,     0,     0,     0,   574,     0,     0,     0,
       0,     0,     0,     0,     0,   575,   576,     0,     0,   580,
     581,   582,   583,   584,   585,   586,     0,     0,   587,   579,
    1022,   574,   572,     0,     0,     0,   577,     0,     0,     0,
     575,   576,   573,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,     0,     0,     0,     0,     0,     0,     0,
       0,   577,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   574,     0,     0,     0,     0,     0,
       0,     0,     0,   575,   576,     0,   578,     0,     0,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
       0,     0,     0,     0,   577,     0,     0,     0,     0,   571,
       0,   578,     0,     0,   580,   581,   582,   583,   584,   585,
     586,     0,     0,   587,     0,  1037,     0,     0,   579,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   561,   562,   563,   564,   565,   566,   567,   568,
     569,   570,     0,   579,   578,   571,     0,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   572,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   573,
       0,     0,     0,     0,     0,     0,   579,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   571,     0,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,   574,   587,   571,  1056,   572,     0,     0,     0,     0,
     575,   576,     0,     0,     0,   573,     0,     0,   580,   581,
     582,   583,   584,   585,   586,     0,     0,   587,     0,  1060,
       0,   577,     0,     0,     0,     0,     0,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,   574,     0,     0,
       0,     0,     0,     0,     0,     0,   575,   576,   572,     0,
       0,   580,   581,   582,   583,   584,   585,   586,   573,     0,
     587,     0,  1065,   572,     0,     0,     0,   577,     0,     0,
       0,   578,     0,   573,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,     0,     0,     0,     0,     0,
     574,     0,     0,   571,     0,     0,     0,     0,     0,   575,
     576,     0,     0,     0,     0,   574,     0,     0,     0,     0,
       0,     0,     0,   579,   575,   576,     0,   578,     0,     0,
     577,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   577,     0,     0,     0,     0,
     571,     0,   561,   562,   563,   564,   565,   566,   567,   568,
     569,   570,     0,     0,     0,     0,     0,     0,     0,   579,
       0,     0,     0,   572,     0,     0,     0,     0,     0,     0,
     578,     0,     0,   573,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   578,     0,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,   580,   581,
     582,   583,   584,   585,   586,   574,     0,   587,   571,  1066,
     572,     0,   579,     0,   575,   576,     0,     0,     0,     0,
     573,     0,     0,     0,     0,     0,     0,   579,     0,     0,
       0,     0,     0,     0,     0,   577,     0,     0,     0,     0,
       0,     0,     0,     0,   580,   581,   582,   583,   584,   585,
     586,     0,   574,   587,   571,  1067,     0,     0,     0,     0,
       0,   575,   576,     0,     0,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,     0,     0,   572,     0,
       0,     0,   577,     0,     0,   578,     0,     0,   573,     0,
       0,     0,     0,     0,     0,     0,     0,   580,   581,   582,
     583,   584,   585,   586,     0,     0,   587,     0,  1068,     0,
       0,     0,   580,   581,   582,   583,   584,   585,   586,     0,
     574,   587,     0,  1096,   572,     0,     0,   579,     0,   575,
     576,   571,   578,     0,   573,     0,     0,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
     577,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   574,     0,     0,     0,
       0,     0,     0,     0,   579,   575,   576,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   577,     0,     0,     0,
     578,   572,     0,     0,   571,     0,     0,     0,     0,     0,
       0,   573,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,     0,  1101,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   579,   574,     0,     0,   578,     0,     0,     0,
       0,     0,   575,   576,     0,     0,     0,     0,     0,   580,
     581,   582,   583,   584,   585,   586,     0,     0,   587,     0,
    1118,     0,     0,   577,  1629,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   573,     0,     0,     0,   579,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
       0,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,     0,     0,     0,     0,     0,   574,     0,     0,     0,
       0,     0,     0,   578,     0,   575,   576,   580,   581,   582,
     583,   584,   585,   586,     0,     0,   587,     0,  1121,     0,
       0,     0,     0,     0,     0,     0,   577,     0,     0,     0,
       0,     0,     0,     0,     0,   571,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   579,     0,   571,     0,     0,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,     0,  1621,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   578,     0,     0,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
       0,     0,   561,   562,   563,   564,   565,   566,   567,   568,
     569,   570,     0,     0,     0,   572,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   573,     0,   572,   579,     0,
       0,     0,     0,     0,     0,     0,     0,   573,     0,     0,
     580,   581,   582,   583,   584,   585,   586,     0,     0,   587,
       0,  1628,     0,     0,     0,   571,     0,   574,     0,     0,
       0,     0,     0,     0,     0,     0,   575,   576,   571,   574,
       0,     0,     0,     0,     0,     0,     0,     0,   575,   576,
       0,     0,     0,     0,     0,     0,     0,   577,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   577,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,     0,  1630,   572,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   573,     0,   578,   572,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   573,   578,
     561,   562,   563,   564,   565,   566,   567,   568,   569,   570,
       0,     0,     0,     0,     0,     0,     0,   574,     0,     0,
       0,     0,     0,     0,     0,     0,   575,   576,     0,   579,
     574,     0,     0,     0,     0,     0,     0,     0,     0,   575,
     576,   579,     0,     0,     0,     0,     0,   577,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     577,     0,     0,     0,     0,     0,   571,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   578,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
     578,     0,     0,     0,   580,   581,   582,   583,   584,   585,
     586,     0,     0,   587,     0,  1631,   580,   581,   582,   583,
     584,   585,   586,   571,     0,   587,   572,  1634,     0,   579,
       0,     0,     0,     0,     0,     0,   573,     0,     0,     0,
       0,     0,   579,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   571,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,     0,     0,   574,     0,
       0,     0,     0,     0,     0,     0,     0,   575,   576,     0,
       0,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,     0,     0,   572,     0,     0,     0,     0,   577,     0,
       0,     0,     0,   573,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,   580,   581,   582,   583,   584,   585,
     586,   571,     0,   587,   572,  1643,     0,   580,   581,   582,
     583,   584,   585,   586,   573,   574,   587,     0,  1644,     0,
       0,     0,     0,     0,   575,   576,     0,   571,   578,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   577,   574,     0,     0,     0,
     571,     0,     0,     0,     0,   575,   576,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
     579,   572,     0,     0,     0,     0,   577,     0,     0,     0,
       0,   573,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   578,     0,   572,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   573,     0,     0,
       0,     0,     0,   574,     0,     0,     0,     0,     0,     0,
     572,     0,   575,   576,   571,     0,   578,     0,     0,     0,
     573,     0,     0,     0,     0,     0,     0,   579,     0,   574,
       0,     0,     0,   577,     0,     0,     0,     0,   575,   576,
       0,     0,     0,     0,     0,   580,   581,   582,   583,   584,
     585,   586,   574,     0,   587,     0,  1647,     0,   579,   577,
       0,   575,   576,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   577,   578,   572,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   573,     0,     0,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,     0,     0,   578,
       0,     0,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,     0,  1649,     0,   579,   574,     0,     0,     0,
       0,     0,   578,     0,     0,   575,   576,     0,     0,     0,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,   579,   587,     0,  1652,     0,   577,     0,     0,     0,
       0,     0,     0,   571,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   579,     0,     0,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   578,     0,     0,     0,
     580,   581,   582,   583,   584,   585,   586,     0,     0,   587,
       0,  1656,   561,   562,   563,   564,   565,   566,   567,   568,
     569,   570,     0,   572,     0,     0,   580,   581,   582,   583,
     584,   585,   586,   573,   571,   587,     0,  1663,   579,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   580,
     581,   582,   583,   584,   585,   586,     0,     0,   587,     0,
    1672,     0,     0,     0,     0,   574,     0,     0,     0,     0,
       0,     0,     0,     0,   575,   576,     0,     0,   571,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   577,     0,     0,     0,     0,
       0,     0,     0,     0,   572,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   573,     0,     0,     0,     0,     0,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,     0,  1673,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   578,   574,     0,   572,     0,
       0,     0,     0,     0,     0,   575,   576,     0,   573,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,     0,
       0,     0,     0,     0,     0,     0,   577,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   579,     0,     0,
     574,     0,     0,     0,     0,     0,     0,     0,     0,   575,
     576,     0,     0,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,     0,     0,     0,     0,     0,     0,     0,
     577,     0,     0,     0,     0,   571,   578,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,     0,     0,     0,
     561,   562,   563,   564,   565,   566,   567,   568,   569,   570,
       0,     0,     0,     0,     0,     0,     0,     0,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,   579,   571,
     578,     0,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,     0,  1682,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   571,     0,   572,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   573,   571,     0,     0,     0,
       0,     0,   579,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   571,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   574,     0,   572,
       0,     0,     0,     0,     0,     0,   575,   576,     0,   573,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,   572,  1684,     0,     0,   577,     0,     0,
       0,     0,     0,   573,     0,     0,   572,     0,     0,     0,
       0,   574,     0,     0,     0,     0,   573,     0,     0,     0,
     575,   576,     0,     0,   572,     0,     0,   580,   581,   582,
     583,   584,   585,   586,   573,   574,   587,     0,  1685,     0,
       0,   577,     0,     0,   575,   576,     0,   578,   574,     0,
       0,     0,     0,     0,     0,     0,     0,   575,   576,     0,
       0,     0,     0,     0,     0,   577,   574,     0,     0,     0,
       0,     0,     0,     0,     0,   575,   576,     0,   577,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   579,
       0,   578,     0,     0,     0,     0,   577,     0,     0,     0,
       0,     0,     0,   561,   562,   563,   564,   565,   566,   567,
     568,   569,   570,     0,     0,   578,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,     0,     0,   578,     0,
       0,     0,     0,   579,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,     0,   578,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,   579,     0,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,   571,
     579,     0,     0,     0,   580,   581,   582,   583,   584,   585,
     586,     0,   571,   587,     0,  1686,     0,     0,   579,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     571,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   571,     0,     0,     0,     0,   580,   581,
     582,   583,   584,   585,   586,   571,     0,   587,     0,  1878,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   572,
       0,     0,   580,   581,   582,   583,   584,   585,   586,   573,
       0,   587,   572,  1879,     0,   580,   581,   582,   583,   584,
     585,   586,   573,     0,   587,     0,  1880,     0,     0,     0,
     572,     0,     0,   580,   581,   582,   583,   584,   585,   586,
     573,   574,   587,   572,  2020,     0,     0,     0,     0,     0,
     575,   576,     0,   573,   574,   572,     0,     0,     0,     0,
       0,     0,     0,   575,   576,   573,     0,     0,     0,     0,
       0,   577,   574,     0,     0,     0,     0,     0,     0,     0,
       0,   575,   576,     0,   577,   574,     0,     0,     0,     0,
       0,     0,     0,     0,   575,   576,     0,   574,     0,     0,
       0,     0,   577,     0,     0,     0,   575,   576,     0,     0,
       0,     0,     0,     0,     0,   577,     0,     0,     0,     0,
       0,   578,     0,     0,     0,     0,     0,   577,     0,     0,
       0,     0,     0,     0,   578,     0,     0,     0,     0,     0,
     561,   562,   563,   564,   565,   566,   567,   568,   569,   570,
       0,     0,   578,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   579,     0,   578,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,   579,   578,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
       0,     0,     0,     0,   579,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   571,   579,     0,   561,
     562,   563,   564,   565,   566,   567,   568,   569,   570,   579,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   571,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   571,     0,     0,     0,   580,   581,
     582,   583,   584,   585,   586,     0,     0,   587,     0,  2027,
       0,   580,   581,   582,   583,   584,   585,   586,     0,     0,
     587,     0,  2028,     0,     0,   571,   572,     0,     0,   580,
     581,   582,   583,   584,   585,   586,   573,     0,   587,     0,
    2029,     0,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,   572,  2031,   580,   581,   582,   583,   584,   585,
     586,     0,   573,   587,   572,  2032,     0,     0,   574,     0,
       0,     0,     0,     0,   573,     0,     0,   575,   576,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   574,   572,     0,     0,   577,     0,
       0,     0,     0,   575,   576,   573,   574,     0,     0,     0,
       0,     0,     0,     0,     0,   575,   576,     0,     0,     0,
       0,     0,     0,     0,   577,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   577,   574,     0,     0,
       0,     0,     0,     0,     0,     0,   575,   576,   578,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   577,     0,     0,
       0,     0,     0,     0,   578,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   578,     0,     0,     0,
     579,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   579,   578,     0,     0,
       0,     0,     0,     0,     0,     0,   657,     0,   579,     0,
       0,     0,     0,     0,     0,     0,   658,     0,     0,   659,
       0,   660,     0,   661,     0,   662,     0,     0,     0,     0,
     663,     0,     0,     0,     0,     0,     0,     0,   664,   579,
       0,     0,     0,   665,   666,     0,     0,     0,     0,     0,
       0,   667,     0,     0,   668,   580,   581,   582,   583,   584,
     585,   586,     0,     0,   587,     0,  2033,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   580,   581,   582,   583,   584,   585,   586,     0,     0,
     587,     0,  2034,   580,   581,   582,   583,   584,   585,   586,
       0,   670,   587,     0,  2259,     0,     0,     0,     0,     0,
       0,   671,     0,     0,     0,     0,    85,    86,    87,    88,
      89,     0,   672,     0,   580,   581,   582,   583,   584,   585,
     586,     0,     0,   587,    90,  2362,     0,    91,    92,    93,
       0,    94,    95,    96,     0,     0,     0,    97,     0,    98,
       0,    99,   100,   101,     0,   102,     0,     0,   103,     0,
     104,     0,     0,   105,     0,     0,   106,   107,   108,   109,
     110,   111,     0,     0,   112,   113,   114,     0,   115,     0,
     116,   117,     0,     0,   118,   119,     0,     0,     0,   673,
     120,   121,   122,   123,     0,   124,   125,   126,     0,   674,
     127,   675,     0,   128,   129,     0,   130,     0,     0,   131,
       0,     0,     0,   132,     0,   676,   133,     0,     0,   134,
     135,     0,   136,   137,     0,     0,   138,   139,     0,   140,
     141,   142,   143,     0,     0,     0,     0,   144,     0,   145,
     677,   146,     0,     0,     0,   147,     0,     0,   148,   149,
       0,     0,   150,     0,     0,   151,     0,     0,   152,   153,
       0,     0,     0,     0,     0,   154,     0,     0,     0,   155,
       0,   156,     0,     0,     0,   157,   158,   159,   160,   161,
     162,   163,     0,   164,   165,     0,   166,   167,   168,   169,
     170,   171,   172,   173,   174,   175,     0,   176,   177,     0,
     178,     0,     0,   179,     0,   180,     0,     0,     0,     0,
       0,     0,     0,   181,   182,     0,     0,     0,   183,   184,
     185,   186,   187,   188,   189,   190,     0,     0,     0,     0,
     191,     0,   192,     0,   193,   194,     0,     0,   195,   196,
     197,     0,   198,   199,   200,     0,     0,   201,     0,   202,
       0,     0,   203,     0,     0,     0,     0,   204,   205,     0,
       0,     0,     0,     0,     0,   206,   207,     0,     0,     0,
     208,     0,     0,     0,   209,     0,     0,     0,   210,     0,
     211,     0,     0,     0,   212,     0,   213,   214,     0,     0,
     215,   216,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   217,     0,   218,     0,   219,   220,   221,   222,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   223,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   224,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   225,   226,     0,   227,     0,     0,     0,     0,
       0,     0,     0,   228,   229,   230,   231,     0,   232,     0,
       0,     0,     0,     0,     0,   233,   234,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   235,     0,   236,     0,     0,   237,     0,     0,   238,
       0,   239,     0,   240,   241,   242,     0,     0,     0,     0,
    1313,    85,    86,    87,    88,    89,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    90,
       0,     0,    91,    92,    93,     0,    94,    95,    96,     0,
       0,     0,    97,     0,    98,     0,    99,   100,   101,     0,
     102,     0,     0,   103,     0,   104,     0,     0,   105,     0,
       0,   106,   107,   108,   109,   110,   111,     0,     0,   112,
     113,   114,     0,   115,     0,   116,   117,     0,     0,   118,
     119,     0,     0,     0,     0,   120,   121,   122,   123,     0,
     124,   125,   126,     0,     0,   127,     0,     0,   128,   129,
       0,   130,     0,     0,   131,     0,     0,     0,   132,     0,
       0,   133,     0,     0,   134,   135,     0,   136,   137,     0,
       0,   138,   139,     0,   140,   141,   142,   143,     0,     0,
       0,     0,   144,     0,   145,     0,   146,     0,     0,     0,
     147,     0,     0,   148,   149,     0,     0,   150,     0,     0,
     151,     0,     0,   152,   153,     0,     0,     0,     0,     0,
     154,     0,     0,     0,   155,     0,   156,     0,     0,     0,
     157,   158,   159,   160,   161,   162,   163,     0,   164,   165,
       0,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,     0,   176,   177,     0,   178,     0,     0,   179,     0,
     180,     0,     0,     0,     0,     0,     0,     0,   181,   182,
       0,     0,     0,   183,   184,   185,   186,   187,   188,   189,
     190,     0,     0,     0,     0,   191,     0,   192,     0,   193,
     194,     0,     0,   195,   196,   197,     0,   198,   199,   200,
       0,     0,   201,     0,   202,     0,     0,   203,     0,     0,
       0,     0,   204,   205,     0,     0,     0,     0,     0,     0,
     206,   207,     0,     0,     0,   208,     0,     0,     0,   209,
       0,     0,     0,   210,     0,   211,     0,     0,     0,   212,
       0,   213,   214,     0,     0,   215,   216,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   217,     0,   218,
       0,   219,   220,   221,   222,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   223,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     224,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   225,   226,     0,
     227,     0,     0,     0,     0,     0,     0,     0,   228,   229,
     230,   231,     0,   232,     0,     0,     0,     0,     0,     0,
     233,   234,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   235,     0,   236,     0,
       0,   237,     0,     0,   238,     0,   239,     0,   240,   241,
     242,     0,     0,     0,     0,  1714,    85,    86,    87,    88,
      89,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    90,     0,     0,    91,    92,    93,
       0,    94,    95,    96,     0,     0,     0,    97,     0,    98,
       0,    99,   100,   101,     0,   102,     0,     0,   103,     0,
     104,     0,     0,   105,     0,     0,   106,   107,   108,   109,
     110,   111,     0,     0,   112,   113,   114,     0,   115,     0,
     116,   117,     0,     0,   118,   119,     0,     0,     0,     0,
     120,   121,   122,   123,     0,   124,   125,   126,     0,     0,
     127,     0,     0,   128,   129,     0,   130,     0,     0,   131,
       0,     0,     0,   132,     0,     0,   133,     0,     0,   134,
     135,     0,   136,   137,     0,     0,   138,   139,     0,   140,
     141,   142,   143,     0,     0,     0,     0,   144,     0,   145,
       0,   146,     0,     0,     0,   147,     0,     0,   148,   149,
       0,     0,   150,     0,     0,   151,     0,     0,   152,   153,
       0,     0,     0,     0,     0,   154,     0,     0,     0,   155,
       0,   156,     0,     0,     0,   157,   158,   159,   160,   161,
     162,   163,     0,   164,   165,     0,   166,   167,   168,   169,
     170,   171,   172,   173,   174,   175,     0,   176,   177,     0,
     178,     0,     0,   179,     0,   180,     0,     0,     0,     0,
       0,     0,     0,   181,   182,     0,     0,     0,   183,   184,
     185,   186,   187,   188,   189,   190,     0,     0,     0,     0,
     191,     0,   192,     0,   193,   194,     0,     0,   195,   196,
     197,     0,   198,   199,   200,     0,     0,   201,     0,   202,
       0,     0,   203,     0,     0,     0,     0,   204,   205,     0,
       0,     0,     0,     0,     0,   206,   207,     0,     0,     0,
     208,     0,     0,     0,   209,     0,     0,     0,   210,     0,
     211,     0,     0,     0,   212,     0,   213,   214,     0,     0,
     215,   216,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   217,     0,   218,     0,   219,   220,   221,   222,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   223,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   224,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   225,   226,     0,   227,     0,     0,     0,     0,
       0,     0,     0,   228,   229,   230,   231,     0,   232,     0,
       0,     0,     0,     0,     0,   233,   234,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   235,     0,   236,     0,     0,   237,     0,     0,   238,
       0,   239,     0,   240,   241,   242,     0,     0,     0,     0,
    1740,    85,    86,    87,    88,    89,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    90,
       0,     0,    91,    92,    93,     0,    94,    95,    96,     0,
       0,     0,    97,     0,    98,     0,    99,   100,   101,     0,
     102,     0,     0,   103,     0,   104,     0,     0,   105,     0,
       0,   106,   107,   108,   109,   110,   111,     0,     0,   112,
     113,   114,     0,   115,     0,   116,   117,     0,     0,   118,
     119,     0,     0,     0,     0,   120,   121,   122,   123,     0,
     124,   125,   126,     0,     0,   127,     0,     0,   128,   129,
       0,   130,     0,     0,   131,     0,     0,     0,   132,     0,
       0,   133,     0,     0,   134,   135,     0,   136,   137,     0,
       0,   138,   139,     0,   140,   141,   142,   143,     0,     0,
       0,     0,   144,     0,   145,     0,   146,     0,     0,     0,
     147,     0,     0,   148,   149,     0,     0,   150,     0,     0,
     151,     0,     0,   152,   153,     0,     0,     0,     0,     0,
     154,     0,     0,     0,   155,     0,   156,     0,     0,     0,
     157,   158,   159,   160,   161,   162,   163,     0,   164,   165,
       0,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,     0,   176,   177,     0,   178,     0,     0,   179,     0,
     180,     0,     0,     0,     0,     0,     0,     0,   181,   182,
       0,     0,     0,   183,   184,   185,   186,   187,   188,   189,
     190,     0,     0,     0,     0,   191,     0,   192,     0,   193,
     194,     0,     0,   195,   196,   197,     0,   198,   199,   200,
       0,     0,   201,     0,   202,     0,     0,   203,     0,     0,
       0,     0,   204,   205,     0,     0,     0,     0,     0,     0,
     206,   207,     0,     0,     0,   208,     0,     0,     0,   209,
       0,     0,     0,   210,     0,   211,     0,     0,     0,   212,
       0,   213,   214,     0,     0,   215,   216,   561,   562,   563,
     564,   565,   566,   567,   568,   569,   570,   217,     0,   218,
       0,   219,   220,   221,   222,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   223,   561,   562,   563,   564,   565,
     566,   567,   568,   569,   570,     0,     0,     0,     0,     0,
     224,   561,   562,   563,   564,   565,   566,   567,   568,   569,
     570,     0,     0,     0,     0,     0,     0,   225,   226,     0,
     227,     0,     0,   571,     0,     0,     0,     0,   228,   229,
     230,   231,     0,   232,     0,     0,     0,     0,     0,     0,
     233,   234,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   571,  1013,     0,     0,     0,   235,     0,   236,     0,
       0,   237,     0,     0,   238,     0,   239,   571,   240,   241,
     242,     0,     0,     0,     0,  2047,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   572,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   573,   561,   562,   563,   564,   565,   566,
     567,   568,   569,   570,     0,     0,     0,     0,     0,     0,
       0,   572,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   573,     0,     0,     0,   574,     0,   572,     0,     0,
       0,     0,     0,     0,   575,   576,     0,   573,   561,   562,
     563,   564,   565,   566,   567,   568,   569,   570,     0,     0,
       0,     0,     0,   574,     0,   577,     0,     0,     0,     0,
     571,     0,   575,   576,     0,     0,     0,     0,     0,   574,
       0,     0,     0,     0,     0,     0,     0,     0,   575,   576,
       0,     0,     0,   577,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   577,
       0,     0,     0,     0,   571,   578,     0,     0,     0,     0,
       0,     0,     0,  1069,  1070,  1071,  1072,  1073,  1074,  1075,
    1076,  1077,  1078,     0,     0,     0,     0,     0,     0,     0,
     572,     0,     0,   578,     0,     0,     0,     0,     0,     0,
     573,     0,     0,     0,     0,     0,     0,   579,     0,   578,
       0,     0,     0,     0,     0,     0,     0,     0,   767,   768,
     769,   770,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   574,     0,   572,   579,   771,   772,   773,  1079,
       0,   575,   576,     0,   573,     0,     0,     0,   774,   775,
       0,   579,   776,     0,     0,     0,     0,     0,     0,     0,
       0,   777,   577,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   574,     0,   778,   779,
       0,     0,     0,     0,     0,   575,   576,     0,     0,     0,
       0,     0,   580,   581,   582,   583,   584,   585,   586,     0,
       0,   587,     0,     0,     0,     0,   577,     0,     0,  1080,
       0,     0,   578,     0,     0,     0,     0,     0,     0,  1081,
     580,   581,   582,   583,   584,   585,   586,  1637,     0,   587,
       0,     0,     0,     0,     0,     0,   580,   581,   582,   583,
     584,   585,   586,     0,     0,   587,     0,     0,     0,     0,
       0,  1082,     0,     0,   579,     0,   578,     0,     0,     0,
    1083,  1084,  1140,  1141,  1142,  1143,  1144,  1145,  1146,  1147,
    1148,  1149,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  1085,     0,     0,     0,     0,     0,  1140,  1141,  1142,
    1143,  1144,  1145,  1146,  1147,  1148,  1149,     0,   579,  1140,
    1141,  1142,  1143,  1144,  1145,  1146,  1147,  1148,  1149,     0,
    1140,  1141,  1142,  1143,  1144,  1145,  1146,  1147,  1148,  1149,
       0,     0,     0,     0,     0,     0,     0,     0,  1150,     0,
    2021,  1086,     0,     0,     0,     0,     0,     0,     0,   580,
     581,   582,   583,   584,   585,   586,     0,     0,   587,     0,
       0,     0,     0,  1420,     0,  1140,  1141,  1142,  1143,  1144,
    1145,  1146,  1147,  1148,  1149,  1668,     0,     0,     0,     0,
       0,     0,     0,  1087,     0,     0,  1696,     0,     0,     0,
       0,     0,     0,   580,   581,   582,   583,   584,   585,   586,
       0,     0,   587,     0,     0,     0,     0,     0,  1151,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1152,     0,
    1140,  1141,  1142,  1143,  1144,  1145,  1146,  1147,  1148,  1149,
       0,  1870,     0,  1151,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  1152,     0,  1151,     0,     0,     0,     0,
    1153,     0,     0,     0,     0,  1152,  1151,     0,     0,  1154,
    1155,     0,     0,     0,     0,     0,  1152,     0,  1088,  1089,
    1090,  1091,  1092,  1093,  1094,  1153,     0,  1095,     0,     0,
    1156,     0,     0,     0,  1154,  1155,  1885,  1153,     0,     0,
       0,     0,     0,     0,     0,     0,  1154,  1155,  1153,     0,
       0,  1151,     0,     0,     0,  1156,     0,  1154,  1155,     0,
       0,  1152,     0,     0,     0,     0,     0,  1156,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1156,     0,
    1157,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  1153,     0,     0,     0,     0,     0,     0,
       0,     0,  1154,  1155,     0,  1157,  1151,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  1152,  1157,     0,     0,
       0,     0,  1158,  1156,     0,     0,     0,     0,  1157,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1158,  1153,     0,
       0,     0,     0,     0,     0,     0,     0,  1154,  1155,  1158,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    1158,     0,     0,  1157,     0,     0,     0,     0,  1156,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1159,  1160,  1161,
    1162,  1163,  1164,  1165,     0,  1158,  1166,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1157,     0,
       0,     0,  1159,  1160,  1161,  1162,  1163,  1164,  1165,     0,
       0,  1166,     0,     0,  1159,  1160,  1161,  1162,  1163,  1164,
    1165,     0,     0,  1166,     0,  1159,  1160,  1161,  1162,  1163,
    1164,  1165,     0,     0,  1166,     0,     0,     0,     0,     0,
    1158,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    1159,  1160,  1161,  1162,  1163,  1164,  1165,     0,     0,  1166,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,    85,    86,    87,    88,    89,     0,
       0,     0,     0,     0,     0,  1159,  1160,  1161,  1162,  1163,
    1164,  1165,    90,     0,  1166,    91,    92,    93,     0,    94,
      95,    96,     0,     0,     0,    97,     0,    98,     0,    99,
     100,   101,     0,   102,     0,     0,   103,     0,   104,     0,
       0,   105,     0,     0,   106,   107,   108,   109,   110,   111,
       0,     0,   112,   113,   114,     0,   115,     0,   116,   117,
       0,     0,   118,   119,     0,     0,     0,     0,   120,   121,
     122,   123,     0,   124,   125,   126,     0,     0,   127,     0,
       0,   128,   129,     0,   130,     0,     0,   131,     0,     0,
       0,   132,     0,     0,   133,     0,     0,   134,   135,     0,
     136,   137,     0,     0,   138,   139,     0,   140,   141,   142,
     143,     0,     0,     0,     0,   144,     0,   145,     0,   146,
       0,     0,     0,   147,   951,     0,   148,   149,     0,     0,
     150,     0,     0,   151,     0,     0,   152,   153,     0,     0,
       0,     0,     0,   154,     0,     0,     0,   155,     0,   156,
       0,     0,     0,   157,   158,   159,   160,   161,   162,   163,
       0,   164,   165,     0,   166,   167,   168,   169,   170,   171,
     172,   173,   174,   175,     0,   176,   177,     0,   178,     0,
       0,   179,     0,   180,     0,     0,     0,     0,     0,     0,
       0,   181,   182,     0,     0,     0,   183,   184,   185,   186,
     187,   188,   189,   190,     0,     0,     0,     0,   191,     0,
     192,     0,   193,   194,     0,     0,   195,   196,   197,     0,
     198,   199,   200,     0,     0,   201,     0,   202,     0,     0,
     203,     0,   952,     0,     0,   204,   205,     0,     0,     0,
       0,     0,     0,   206,   207,     0,     0,     0,   208,     0,
       0,     0,   209,     0,     0,     0,   210,     0,   211,     0,
       0,     0,   212,     0,   213,   214,     0,     0,   215,   216,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     217,     0,   218,     0,   219,   220,   221,   222,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   223,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   224,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     225,   226,     0,   227,     0,     0,     0,     0,     0,     0,
       0,   228,   229,   230,   231,     0,   232,     0,     0,     0,
       0,     0,     0,   233,   234,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   235,
       0,   236,     0,     0,   237,     0,     0,   238,     0,   239,
       0,   240,   241,   242,    85,    86,    87,    88,    89,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    90,     0,     0,    91,    92,    93,     0,    94,
      95,    96,     0,     0,     0,    97,     0,    98,     0,    99,
     100,   101,     0,   102,     0,     0,   103,     0,   104,     0,
       0,   105,     0,     0,   106,   107,   108,   109,   110,   111,
       0,     0,   112,   113,   114,     0,   115,     0,   116,   117,
       0,     0,   118,   119,     0,     0,     0,     0,   120,   121,
     122,   123,     0,   124,   125,   126,     0,     0,   127,     0,
       0,   128,   129,     0,   130,     0,     0,   131,     0,     0,
       0,   132,     0,     0,   133,     0,     0,   134,   135,     0,
     136,   137,     0,     0,   138,   139,     0,   140,   141,   142,
     143,     0,     0,     0,     0,   144,     0,   145,     0,   146,
       0,     0,     0,   147,     0,     0,   148,   149,     0,     0,
     150,     0,     0,   151,     0,     0,   152,   153,     0,     0,
       0,     0,     0,   154,   555,     0,     0,   155,     0,   156,
       0,     0,     0,   157,   158,   159,   160,   161,   162,   163,
       0,   164,   165,     0,   166,   167,   168,   169,   170,   171,
     172,   173,   174,   175,     0,   176,   177,     0,   178,     0,
       0,   179,     0,   180,     0,     0,     0,     0,     0,     0,
       0,   181,   182,     0,     0,     0,   183,   184,   185,   186,
     187,   188,   189,   190,     0,     0,     0,     0,   191,     0,
     192,     0,   193,   194,     0,     0,   195,   196,   197,     0,
     198,   199,   200,     0,     0,   201,     0,   202,     0,     0,
     203,     0,   556,     0,     0,   204,   205,     0,     0,     0,
       0,     0,     0,   206,   207,     0,     0,     0,   208,     0,
       0,     0,   209,     0,     0,     0,   210,     0,   211,     0,
       0,     0,   212,     0,   213,   214,     0,     0,   215,   216,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     217,     0,   218,     0,   219,   220,   221,   222,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   223,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   224,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     225,   226,     0,   227,     0,     0,     0,     0,     0,     0,
       0,   228,   229,   230,   231,     0,   232,     0,     0,     0,
       0,     0,     0,   233,   234,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   235,
       0,   236,     0,     0,   237,     0,     0,   238,     0,   239,
       0,   240,   241,   242,    85,    86,    87,    88,    89,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    90,     0,     0,    91,    92,    93,     0,    94,
      95,    96,     0,     0,     0,    97,     0,    98,     0,    99,
     100,   101,     0,   102,     0,     0,   103,     0,   104,     0,
       0,   105,     0,     0,   106,   107,   108,   109,   110,   111,
       0,     0,   112,   113,   114,     0,   115,     0,   116,   117,
       0,     0,   118,   119,     0,     0,  1710,     0,   120,   121,
     122,   123,     0,   124,   125,   126,     0,     0,   127,     0,
       0,   128,   129,     0,   130,     0,     0,   131,     0,     0,
       0,   132,     0,     0,   133,     0,     0,   134,   135,     0,
     136,   137,     0,     0,   138,   139,     0,   140,   141,   142,
     143,     0,     0,     0,     0,   144,     0,   145,     0,   146,
       0,     0,     0,   147,     0,     0,   148,   149,     0,     0,
     150,     0,     0,   151,     0,     0,   152,   153,     0,     0,
       0,     0,     0,   154,     0,     0,     0,   155,     0,   156,
       0,     0,     0,   157,   158,   159,   160,   161,   162,   163,
       0,   164,   165,     0,   166,   167,   168,   169,   170,   171,
     172,   173,   174,   175,     0,   176,   177,     0,   178,     0,
       0,   179,     0,   180,     0,     0,     0,     0,     0,     0,
       0,   181,   182,     0,     0,     0,   183,   184,   185,   186,
     187,   188,   189,   190,     0,     0,     0,     0,   191,     0,
     192,     0,   193,   194,     0,     0,   195,   196,   197,     0,
     198,   199,   200,     0,     0,   201,     0,   202,     0,     0,
     203,     0,  1711,     0,     0,   204,   205,     0,     0,     0,
       0,     0,     0,   206,   207,     0,     0,     0,   208,     0,
       0,     0,   209,     0,     0,     0,   210,     0,   211,     0,
       0,     0,   212,     0,   213,   214,     0,     0,   215,   216,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     217,     0,   218,     0,   219,   220,   221,   222,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   223,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   224,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     225,   226,     0,   227,     0,     0,     0,     0,     0,     0,
       0,   228,   229,   230,   231,     0,   232,     0,     0,     0,
       0,     0,     0,   233,   234,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   235,
       0,   236,     0,     0,   237,     0,     0,   238,     0,   239,
       0,   240,   241,   242,    85,    86,    87,    88,    89,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    90,     0,     0,    91,    92,    93,     0,    94,
      95,    96,     0,     0,     0,    97,     0,    98,     0,    99,
     100,   101,     0,   102,     0,     0,   103,     0,   104,     0,
       0,   105,     0,     0,   106,   107,   108,   109,   110,   111,
       0,     0,   112,   113,   114,     0,   115,     0,   116,   117,
       0,     0,   118,   119,     0,     0,     0,     0,   120,   121,
     122,   123,     0,   124,   125,   126,     0,     0,   127,     0,
       0,   128,   129,     0,   130,     0,     0,   131,     0,     0,
       0,   132,     0,     0,   133,     0,     0,   134,   135,     0,
     136,   137,     0,     0,   138,   139,     0,   140,   141,   142,
     143,     0,     0,     0,   705,   144,     0,   145,     0,   146,
       0,     0,     0,   147,     0,     0,   148,   149,     0,     0,
     150,     0,     0,   151,     0,     0,   152,   153,     0,     0,
       0,     0,     0,   154,     0,     0,     0,   155,     0,   156,
       0,     0,     0,   157,   158,   159,   160,   161,   162,   163,
       0,   164,   165,     0,   166,   167,   168,   169,   170,   171,
     172,   173,   174,   175,     0,   176,   177,     0,   178,     0,
       0,   179,     0,   180,     0,     0,     0,     0,     0,     0,
       0,   181,   182,     0,     0,     0,   183,   184,   185,   186,
     187,   188,   189,   190,     0,     0,     0,     0,   191,     0,
     192,     0,   193,   194,     0,     0,   195,   196,   197,     0,
     198,   199,   200,     0,     0,   201,     0,   202,     0,     0,
     203,     0,     0,     0,     0,   204,   205,     0,     0,     0,
       0,     0,     0,   206,   207,     0,     0,     0,   208,     0,
       0,     0,   209,     0,     0,     0,   210,     0,   211,     0,
       0,     0,   212,     0,   213,   214,     0,     0,   215,   216,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     217,     0,   218,     0,   219,   220,   221,   222,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   223,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   224,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     225,   226,     0,   227,     0,     0,     0,     0,     0,     0,
       0,   228,   229,   230,   231,     0,   232,     0,     0,     0,
       0,     0,     0,   233,   234,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   235,
       0,   236,     0,     0,   237,     0,     0,   238,     0,   239,
       0,   240,   241,   242,    85,    86,    87,    88,    89,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    90,     0,     0,    91,    92,    93,     0,    94,
      95,    96,     0,     0,     0,    97,     0,    98,     0,    99,
     100,   101,     0,   102,     0,     0,   103,     0,   104,     0,
       0,   105,     0,     0,   106,   107,   108,   109,   110,   111,
       0,     0,   112,   113,   114,     0,   115,     0,   116,   117,
       0,     0,   118,   119,     0,     0,     0,     0,   120,   121,
     122,   123,     0,   124,   125,   126,     0,     0,   127,     0,
       0,   128,   129,     0,   130,     0,     0,   131,     0,     0,
       0,   132,     0,     0,   133,     0,     0,   134,   135,     0,
     136,   137,     0,     0,   138,   139,     0,   140,   141,   142,
     143,     0,     0,     0,     0,   144,     0,   145,     0,   146,
       0,     0,     0,   147,     0,     0,   148,   149,     0,     0,
     150,     0,     0,   151,     0,     0,   152,   153,     0,     0,
       0,     0,     0,   154,     0,     0,     0,   155,     0,   156,
       0,     0,     0,   157,   158,   159,   160,   161,   162,   163,
       0,   164,   165,     0,   166,   167,   168,   169,   170,   171,
     172,   173,   174,   175,     0,   176,   177,     0,   178,     0,
       0,   179,     0,   180,     0,     0,     0,     0,     0,     0,
       0,   181,   182,     0,     0,     0,   183,   184,   185,   186,
     187,   188,   189,   190,     0,     0,     0,     0,   191,     0,
     192,     0,   193,   194,     0,     0,   195,   196,   197,     0,
     198,   199,   200,     0,     0,   201,     0,   202,     0,     0,
     203,     0,  1896,     0,     0,   204,   205,     0,     0,     0,
       0,     0,     0,   206,   207,     0,     0,     0,   208,     0,
       0,     0,   209,     0,     0,     0,   210,     0,   211,     0,
       0,     0,   212,     0,   213,   214,     0,     0,   215,   216,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     217,     0,   218,     0,   219,   220,   221,   222,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   223,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   224,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     225,   226,     0,   227,     0,     0,     0,     0,     0,     0,
       0,   228,   229,   230,   231,     0,   232,     0,     0,     0,
       0,     0,     0,   233,   234,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   235,
       0,   236,     0,     0,   237,     0,     0,   238,     0,   239,
       0,   240,   241,   242,    85,    86,    87,    88,    89,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    90,     0,     0,    91,    92,    93,     0,    94,
      95,    96,     0,     0,     0,    97,     0,    98,     0,    99,
     100,   101,     0,   102,     0,     0,   103,     0,   104,     0,
       0,   105,     0,     0,   106,   107,   108,   109,   110,   111,
       0,     0,   112,   113,   114,     0,   115,     0,   116,   117,
       0,     0,   118,   119,     0,     0,     0,     0,   120,   121,
     122,   123,     0,   124,   125,   126,     0,     0,   127,     0,
       0,   128,   129,     0,   130,     0,     0,   131,     0,     0,
       0,   132,     0,     0,   133,     0,     0,   134,   135,     0,
     136,   137,     0,     0,   138,   139,     0,   140,   141,   142,
     143,     0,     0,     0,     0,   144,     0,   145,     0,   146,
       0,     0,     0,   147,     0,     0,   148,   149,     0,     0,
     150,     0,     0,   151,     0,     0,   152,   153,     0,     0,
       0,     0,     0,   154,     0,     0,     0,   155,     0,   156,
       0,     0,     0,   157,   158,   159,   160,   161,   162,   163,
       0,   164,   165,     0,   166,   167,   168,   169,   170,   171,
     172,   173,   174,   175,     0,   176,   177,     0,   178,     0,
       0,   179,     0,   180,     0,     0,     0,     0,     0,     0,
       0,   181,   182,     0,  2345,     0,   183,   184,   185,   186,
     187,   188,   189,   190,     0,     0,     0,     0,   191,     0,
     192,     0,   193,   194,     0,     0,   195,   196,   197,     0,
     198,   199,   200,     0,     0,   201,     0,   202,     0,     0,
     203,     0,     0,     0,     0,   204,   205,     0,     0,     0,
       0,     0,     0,   206,   207,     0,     0,     0,   208,     0,
       0,     0,   209,     0,     0,     0,   210,     0,   211,     0,
       0,     0,   212,     0,   213,   214,     0,     0,   215,   216,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     217,     0,   218,     0,   219,   220,   221,   222,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   223,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   224,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     225,   226,     0,   227,     0,     0,     0,     0,     0,     0,
       0,   228,   229,   230,   231,     0,   232,     0,     0,     0,
       0,     0,     0,   233,   234,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   235,
       0,   236,     0,     0,   237,     0,     0,   238,     0,   239,
       0,   240,   241,   242,    85,    86,    87,    88,    89,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    90,     0,     0,    91,    92,    93,     0,    94,
      95,    96,     0,     0,     0,    97,     0,    98,     0,    99,
     100,   101,     0,   102,     0,     0,   103,     0,   104,     0,
       0,   105,     0,     0,   106,   107,   108,   109,   110,   111,
       0,     0,   112,   113,   114,     0,   115,     0,   116,   117,
       0,     0,   118,   119,     0,     0,     0,     0,   120,   121,
     122,   123,     0,   124,   125,   126,     0,     0,   127,     0,
       0,   128,   129,     0,   130,     0,     0,   131,     0,     0,
       0,   132,     0,     0,   133,     0,     0,   134,   135,     0,
     136,   137,     0,     0,   138,   139,     0,   140,   141,   142,
     143,     0,     0,     0,     0,   144,     0,   145,     0,   146,
       0,     0,     0,   147,     0,     0,   148,   149,     0,     0,
     150,     0,     0,   151,     0,     0,   152,   153,     0,     0,
       0,     0,     0,   154,     0,     0,     0,   155,     0,   156,
       0,     0,     0,   157,   158,   159,   160,   161,   162,   163,
       0,   164,   165,     0,   166,   167,   168,   169,   170,   171,
     172,   173,   174,   175,     0,   176,   177,     0,   178,     0,
       0,   179,     0,   180,     0,     0,     0,     0,     0,     0,
       0,   181,   182,     0,     0,     0,   183,   184,   185,   186,
     187,   188,   189,   190,     0,     0,     0,     0,   191,     0,
     192,     0,   193,   194,     0,     0,   195,   196,   197,     0,
     198,   199,   200,     0,     0,   201,     0,   202,     0,     0,
     203,     0,     0,     0,     0,   204,   205,     0,     0,     0,
       0,     0,     0,   206,   207,     0,     0,     0,   208,     0,
       0,     0,   209,     0,     0,     0,   210,     0,   211,     0,
       0,     0,   212,     0,   213,   214,     0,     0,   215,   216,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     217,     0,   218,     0,   219,   220,   221,   222,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   223,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   224,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     225,   226,     0,   227,     0,     0,     0,     0,     0,     0,
       0,   228,   229,   230,   231,     0,   232,     0,     0,     0,
       0,     0,     0,   233,   234,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   235,
       0,   236,     0,     0,   237,     0,     0,   238,     0,   239,
       0,   240,   241,   242,    85,    86,    87,   957,    89,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    90,     0,     0,    91,    92,    93,     0,    94,
      95,    96,     0,     0,     0,    97,     0,    98,     0,    99,
     100,   101,     0,   102,     0,     0,   103,     0,   104,     0,
       0,   105,     0,     0,   106,   107,   108,   109,   110,   111,
       0,     0,   112,   113,   114,     0,   115,     0,   116,   117,
       0,     0,   118,   119,     0,     0,     0,     0,   120,   121,
     122,   123,     0,   124,   125,   126,     0,     0,   127,     0,
       0,   128,   129,     0,   130,     0,     0,   131,     0,     0,
       0,   132,     0,     0,   133,     0,     0,   134,   135,     0,
     136,   137,     0,     0,   138,   139,     0,   140,   141,   958,
     143,     0,     0,     0,     0,   144,     0,   145,     0,   146,
       0,     0,     0,   147,     0,     0,   148,   149,     0,     0,
     150,     0,     0,   151,     0,     0,   152,   153,     0,     0,
       0,     0,     0,   154,     0,     0,     0,   155,     0,   156,
       0,     0,     0,   157,   158,   159,   160,   161,   162,   163,
       0,   164,   165,     0,   166,   167,   168,   169,   170,   171,
     172,   173,   174,   175,     0,   176,   177,     0,   178,     0,
       0,   179,     0,   180,     0,     0,     0,     0,     0,     0,
       0,   181,   182,     0,     0,     0,   183,   184,   185,   186,
     187,   188,   189,   190,     0,     0,     0,     0,   191,     0,
     192,     0,   193,   194,     0,     0,   195,   196,   197,     0,
     198,   199,   200,     0,     0,   201,     0,   202,     0,     0,
     203,     0,  1258,     0,  1259,   204,   205,     0,     0,  1260,
       0,  1261,     0,   206,   207,     0,     0,     0,   208,  1262,
       0,     0,   209,     0,     0,     0,   210,     0,   211,     0,
       0,     0,   212,     0,   213,   214,     0,     0,   215,   216,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     217,     0,   218,     0,   219,   220,   221,   222,     0,  1263,
    1264,     0,     0,     0,     0,     0,     0,   223,     0,  1967,
    1968,  1969,  1265,  1266,     0,     0,     0,     0,     0,     0,
       0,     0,  1267,   224,     0,  1268,     0,     0,     0,  1269,
       0,     0,  1270,     0,     0,     0,     0,     0,     0,     0,
     225,   226,     0,   227,     0,     0,     0,     0,     0,     0,
       0,   228,   229,   230,   231,     0,   232,     0,     0,     0,
    1271,     0,     0,   233,   234,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   235,
       0,   236,     0,     0,   237,     0,     0,   238,  1970,   239,
     657,   240,   241,   242,     0,  1272,     0,     0,     0,     0,
     658,     0,  1273,   659,     0,   660,     0,   661,     0,   662,
    1971,     0,     0,  1972,   663,     0,     0,     0,     0,  1274,
       0,     0,   664,  1275,     0,     0,     0,   665,   666,     0,
       0,     0,  1276,  1277,  1278,   667,     0,     0,   668,     0,
    1279,   669,     0,     0,     0,     0,     0,     0,  1280,     0,
       0,     0,     0,     0,     0,     0,  1973,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  1281,     0,     0,
       0,     0,     0,     0,     0,     0,  1282,     0,     0,     0,
       0,     0,     0,     0,     0,   670,     0,     0,     0,     0,
       0,     0,  1283,     0,     0,   671,  1974,  1975,  1976,     0,
       0,  1977,  1978,  1979,  1980,  1981,   672,  1982,  1983,     0,
    1984,  1985,  1986,  1987,  1988,  1989,     0,     0,  1990,     0,
    1991,     0,  1992,  1993,  1994,  1995,  1996,  1997,     0,     0,
    1998,  1999,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  1284,     0,     0,     0,     0,     0,
       0,     0,     0,   673,  1285,     0,     0,  1286,     0,     0,
       0,     0,     0,   674,     0,   675,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   676,
       0,     0,     0,     0,     0,     0,     0,     0,  2000,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   677
};

static const short yycheck[] =
{
       2,   477,     2,   605,    14,   302,   303,   304,   689,   711,
     368,  1479,   461,  1257,   463,   464,   465,   466,   636,   596,
      22,   598,  1300,  1301,  1237,  1303,  1513,  1192,  1241,  1185,
    1288,   528,  1488,   880,   905,     3,  1613,   962,    40,   908,
     489,   490,  1524,  1770,  1314,   914,   517,  1305,    47,  1542,
     858,     3,  1137,    60,    60,  1536,  1212,   396,    51,    34,
    1747,  1542,  1309,    85,  1545,  1546,    68,     3,    68,  1550,
    1551,   483,   484,    82,  1949,    34,   573,    60,   655,   656,
      60,   493,   579,  1262,  1552,     3,  2087,   124,   124,  1576,
     124,     3,     9,  2039,  1562,  1563,   117,  1578,    89,   191,
     138,   117,  1496,   173,  2013,   682,     9,   144,     4,   187,
      34,  2095,   459,    34,   139,   187,    19,   221,   102,     9,
      82,  1603,   192,   243,     3,  1764,    93,    62,    38,  1773,
     134,   103,    89,   263,   242,    95,   242,   121,   715,   242,
     136,    93,   719,   121,    96,   243,    98,  2391,  2149,   883,
    2096,   125,   103,   139,    30,   313,  1312,   178,    74,    76,
    2404,   138,  2094,    75,   150,   121,    36,   142,    22,     6,
     138,   123,    29,   148,   126,    77,   160,   271,   148,   242,
      48,   339,   160,   142,   135,    48,    76,   139,   922,   148,
     162,  1469,   122,   109,    62,   267,   102,    94,   150,  2131,
      62,    71,    78,   105,   160,    62,   190,   234,   138,   184,
     304,   162,   190,   239,   241,   240,   513,   192,   142,  1466,
     264,   142,   903,   229,   148,   184,   102,   148,   253,   203,
    2105,   215,   260,   224,   190,   102,   101,   215,   242,   235,
     233,   243,   258,   110,   237,   282,   543,   207,   356,   216,
     356,   272,   204,   120,   261,   261,   194,  2166,   279,   215,
     184,   236,   271,   184,   266,   119,   268,   224,   192,   290,
     229,   281,   162,   266,   290,  1553,   406,   236,  1556,  1087,
    1558,   291,   119,   189,    60,   260,   406,  1565,  1566,  1567,
    1568,  1935,   317,  1786,   912,   117,   305,   193,  1383,   309,
     918,  1940,   406,   406,   256,  1786,  1519,   654,  2217,   271,
     245,   187,   236,   189,   406,   236,  2300,   301,   214,   229,
    2266,   331,   360,   301,   214,   403,   243,   263,   204,   259,
    1907,   403,  1726,  1727,   404,  2210,   335,   255,  1494,  1208,
     208,  1497,  1498,   406,  1614,   301,   282,   686,  2257,  1434,
    1158,   188,   264,   363,   364,   365,   366,   254,  1537,   856,
    2361,   858,   406,    17,    18,   367,   368,   369,  1615,   406,
     406,   346,   406,     0,   239,   265,   346,   379,   406,   379,
     256,   720,   404,   411,   263,   406,   361,   346,    17,    18,
     406,   361,   360,  2080,   396,   404,   162,   404,   404,   392,
     393,   268,   361,   282,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,   162,   406,   418,   419,   420,   419,
    2329,   404,   346,   425,   404,   346,   428,   429,    17,    18,
     432,   406,   335,   281,     9,   145,   258,   361,     3,   441,
     361,   853,  1982,   291,    19,   155,   294,   406,   214,  1989,
     238,   239,   462,  1946,   406,  1937,  1612,   467,   124,   469,
     470,   471,   472,   473,  2041,  1946,   237,   145,   290,   155,
     480,   481,   482,  1717,   260,   239,    97,   155,   488,   145,
     838,  1728,   406,   411,   494,   406,   117,   497,   159,   243,
     500,   501,   502,   503,   504,   505,   506,   507,   508,   265,
     510,   511,   512,   124,   514,   515,   516,   217,   518,   519,
     520,   521,   522,   523,   524,   525,  1729,   527,    34,   529,
     530,   531,   532,   533,   534,   535,   536,  1771,  2010,  2256,
     379,   217,    93,   187,   544,  1748,   546,   547,   548,   217,
     145,   162,   290,    43,   554,  1021,   183,   178,  2016,   186,
     155,   561,   562,   563,   564,   565,   566,   567,   187,   569,
     570,   571,   123,    63,   235,   575,   576,   577,   578,  1725,
     580,   581,   582,   583,   584,   585,   586,   587,  1386,   127,
    1665,   173,   187,   342,  1081,     3,  1204,   589,   128,  1207,
    1087,     9,  1004,   595,   596,   595,   598,    73,   187,   309,
     192,  1780,   604,  1015,  1016,   187,  1853,   946,  1693,   157,
     112,   113,   217,   267,   404,  1893,  1894,  1486,   408,   127,
     406,   392,   393,   309,  1036,   411,   142,   200,   201,   968,
    1438,   309,   148,  1045,   271,   175,   176,   177,   267,  1051,
      74,   272,    64,   204,    66,  1516,  1058,    34,   279,   157,
     126,  1063,  1499,   655,   656,  1152,  1581,   240,    76,   290,
    2000,  1158,   267,   139,  2004,    35,   303,   304,   184,  2151,
     214,    96,   928,    34,   930,   109,   220,   933,   267,   681,
     682,   681,   239,   231,   686,   267,   230,   689,    58,    82,
     692,   253,   694,   195,   121,   256,  1167,  1168,   123,   139,
     702,   135,   702,   705,   309,   705,  1259,  1260,   342,  1262,
     712,   239,   712,   715,   139,   404,  1929,   719,   720,   404,
     236,  1934,  2178,   231,  1136,   150,   538,   539,   540,   541,
     542,   404,  1285,   160,  1913,  1914,  1915,   747,   242,   241,
     394,   395,   396,   397,   398,   399,   400,   263,   404,   403,
    2008,    89,   187,  1909,  1910,   142,   391,   392,   404,   394,
    2247,   148,   292,   190,   240,   404,   395,   396,   397,   398,
     399,   400,   302,   187,   403,   189,   306,   253,   404,   204,
     256,   142,   209,   210,   187,   404,   189,   148,   215,   394,
     395,   396,   397,   398,   399,   400,   404,   184,   403,   809,
     810,   811,   236,   187,   404,   189,   404,   396,   397,   398,
     399,   400,   405,   406,   403,   411,   398,   399,   400,   405,
     406,   403,   242,   184,   405,   406,   405,   406,   404,   839,
     346,   192,   267,   405,   406,   404,   838,   404,   840,  2052,
     404,   317,   405,   406,   404,   361,   404,   857,    81,   236,
     188,   404,  2124,  2125,   405,   406,  2128,   867,   404,   869,
     405,   406,   404,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,  2145,   301,   236,  2148,   404,   271,   404,
    1238,   274,   275,   405,   406,   895,   224,  1384,    48,  1386,
     406,   229,   404,   895,  2050,  2051,   898,   404,   898,   292,
     133,  2369,    59,   905,   297,   162,   405,   406,   404,   302,
     143,   913,   404,   915,   147,   915,  2081,   405,   406,  2197,
    2198,  2199,   405,   406,  2168,   405,   406,   405,   406,    75,
     405,   406,   934,   404,   934,   405,   406,   404,   940,  1436,
     940,  1438,   404,   945,   946,   404,   179,   180,   404,   182,
     405,   406,   386,   387,   388,   389,   390,   391,   404,   346,
     404,   396,   397,   398,   399,   400,   968,   404,   403,   405,
     406,  2319,  2320,   404,   361,   810,   811,  1914,  1915,     4,
    2341,  2342,   187,   404,   986,   346,   986,   404,   990,   404,
     992,    16,    17,  1003,    19,   404,   404,  1007,   404,   145,
     361,   406,  1012,   404,    29,   404,    31,    32,  1018,   155,
    1020,    36,    37,  1023,  1024,   404,   404,  1493,   405,   406,
    1030,  1433,   404,   404,  1034,   404,   404,   404,   404,   404,
     404,   404,  1042,   404,  1044,   404,   404,   404,  1048,  1049,
    1050,   187,   404,   192,  1054,   406,   404,  1057,  1524,  1059,
     404,  1061,  1062,   404,  1064,   404,   404,   404,   404,  1069,
    1070,  1071,  1072,  1073,  1074,  1075,   116,  1077,  1078,  1079,
    1080,   217,   404,  1083,  1084,  1085,  1086,   404,  1088,  1089,
    1090,  1091,  1092,  1093,  1094,  1095,   404,  1097,  1098,   404,
    1100,   404,  1102,  1103,  1104,   404,   404,   404,   404,  1109,
      88,   264,  1720,   163,   164,   165,   166,   167,   168,   169,
    1120,   171,   172,  1123,  1124,   406,    74,   307,   405,   378,
     405,   267,   405,  1481,   405,   405,    19,  2405,   404,   411,
    1140,  1141,  1142,  1143,  1144,  1145,  1146,    48,  1148,  1149,
    1150,   157,   124,    88,  1154,  1155,  1156,  1157,   159,  1159,
    1160,  1161,  1162,  1163,  1164,  1165,  1166,   406,   255,   398,
      39,   239,   155,   309,   335,   235,    48,  1169,  1770,  1640,
    1641,  1173,   238,  1173,     6,     7,     8,     9,   235,    11,
      12,    13,    14,   124,   406,   262,   240,   238,   100,   194,
     205,   192,   406,   192,   405,   116,   192,   406,  1669,  1670,
     214,   411,   405,   405,   398,   405,   405,  1209,   405,  1209,
     405,  1213,   405,   404,  1216,   124,  1216,   406,  1220,   405,
     405,   405,   405,   405,   397,   405,  1697,  1698,  1230,  1231,
    1230,  1231,   406,   405,   411,   405,  1238,   405,   405,   405,
     320,   321,   322,   323,   115,  1822,  1256,   411,   394,   395,
     396,   397,   398,   399,   400,   411,   189,   403,   338,   339,
     340,   404,   187,   411,   141,    48,   406,   243,    74,   145,
     350,   351,   335,   238,   354,   404,   406,   243,   406,   263,
    1692,     9,     9,   363,  1760,     9,     9,   119,  1290,     9,
       9,     9,     9,     9,   406,   251,   124,    47,   406,   405,
     380,   381,   406,     3,     3,     5,   327,   344,  1310,   344,
       9,   242,   242,   124,   124,   190,   190,   124,   190,   405,
     242,   404,   242,    23,    24,   242,    26,   144,    28,   124,
     411,    31,  1342,    33,  1344,    34,    36,    37,    38,  1349,
    1350,    41,    42,   242,    44,    45,   124,    47,    47,   410,
      62,   242,    52,    53,    54,   411,    56,    57,   411,    59,
      60,    61,    62,   243,    64,   124,    66,   146,   229,    69,
      70,    71,   242,     9,   282,  1385,    48,    76,     9,     9,
      80,  2083,    96,     9,  1394,   114,  1396,     9,   149,   149,
      62,     9,   114,    93,     9,    87,     9,     9,  1408,  1409,
    1410,     9,     9,     9,     9,   105,   106,     9,   229,     9,
    1420,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,     9,   242,   122,   242,   406,   242,  1437,   128,   242,
    1906,   260,   131,   132,   242,   107,  1446,   411,  1448,   138,
     281,   281,   405,   142,   405,   144,   405,   384,   405,   148,
     378,   405,   405,   405,   405,   405,   405,   189,   406,   405,
     265,   405,   404,   406,   136,  1941,   405,   157,   189,   242,
     242,   145,    71,   264,  1476,  1477,   408,    75,   148,  1481,
     148,   404,   398,     9,   199,   184,   153,   159,   198,   404,
     242,   150,   150,   192,     9,   242,   252,   404,   411,   198,
     404,   398,   405,  1505,  1506,   190,   190,   405,  1510,  1511,
    1520,   131,   364,   165,  1516,   411,   346,   341,   406,   219,
     148,   148,  1524,   223,   405,   225,   404,   150,    76,   229,
     229,   150,   405,   205,  1536,   404,   208,   236,   406,   242,
    1542,   242,   282,  1545,  1546,   242,   405,   145,  1550,  1551,
     222,   352,   405,  1555,   144,   406,   255,   155,   406,   259,
     259,   260,   405,   235,   263,    87,   238,   239,   132,     9,
    1572,    95,  1572,   148,   199,   352,  1578,  2026,   148,    87,
    1582,  1583,   264,   282,   406,   214,   242,    60,   102,   187,
    2271,  2272,   406,  2274,   289,   102,   304,   239,   196,   197,
     404,  1603,   404,   156,   404,   404,  2082,   404,   404,   242,
    1620,   121,   404,   148,   404,   189,   405,   404,   242,   217,
     405,   242,  1632,  2035,   134,   242,   305,  1637,  1638,   405,
     404,   190,   190,   404,   190,   404,   335,   150,  1648,   190,
     190,   150,   229,   190,  1654,   190,   190,   346,  1658,   190,
     160,  1661,   405,  2334,  2256,  2336,  2337,   405,  1668,   358,
     360,  1671,   361,    87,  1674,    87,   112,  1677,  1678,   267,
      87,    75,   405,   404,  2355,   260,   260,   242,   194,   189,
     190,   406,   358,   166,    87,    87,  1696,    87,   192,    72,
     190,     9,   405,   404,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,   404,   215,   405,   406,  1710,   405,
     404,   309,   405,   216,   405,   138,   405,   405,   405,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,   190,
     405,   404,   242,   404,    75,   156,  1738,  1747,   170,   405,
     405,     9,   406,  1753,  2150,  1304,   426,  2008,  1603,   261,
    1752,  1964,  1290,  1258,  1585,  1952,  1962,  2005,  1970,  1970,
      75,  2233,  2137,  2101,  2348,   275,  2307,  1777,  2222,  2154,
    2107,  2235,  1581,   971,  1789,   919,  1230,  1181,  1465,    68,
    1759,   617,  2205,  1931,  1786,    75,   296,   297,  1188,  1799,
    1014,   301,   461,   409,  2053,  2404,   394,   395,   396,   397,
     398,   399,   400,   442,  1190,   403,   720,   946,  2389,  1320,
    2082,   409,   474,  1936,   408,   705,   916,   718,   887,   433,
    1822,  1823,  1699,  2264,  2173,   990,  2326,  2278,  1941,  1511,
     145,   895,  2129,  1752,  1836,  1518,  1234,  1839,  1927,  1839,
     155,  1843,  1173,   404,   935,  2195,   940,  1510,  2200,  1920,
    1852,  1738,    -1,    -1,    -1,   145,    -1,    -1,    -1,    -1,
    1870,    -1,    -1,    -1,    -1,   155,    -1,    -1,    -1,    -1,
      -1,    -1,   187,    -1,    -1,  1885,    -1,    -1,    -1,    -1,
      -1,   196,   197,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,  1898,   187,  1908,    -1,
      -1,  1911,   217,    -1,    -1,    -1,   196,   197,    -1,    -1,
      -1,    -1,    -1,  2389,    -1,  2212,  2213,  2214,  1920,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,    -1,    -1,    -1,    27,    -1,    -1,    -1,    -1,  1941,
      33,    -1,    -1,    -1,  1946,    -1,    -1,  1949,    -1,    -1,
    1952,    30,   267,    -1,    -1,    48,    -1,    -1,    -1,    -1,
      -1,    -1,  1964,    -1,    -1,    -1,    -1,    -1,    -1,    62,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   267,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
      -1,    -1,    -1,    -1,   309,    -1,    -1,    -1,    -1,    78,
      79,    -1,    -1,    -1,    -1,    -1,    -1,   100,  2018,    -1,
      -1,  2021,    91,    92,    -1,  2025,    -1,    -1,    -1,   309,
      -1,    -1,   101,    -1,    -1,   104,    -1,    -1,    -1,  2039,
      -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    75,    -1,   139,   140,    -1,    -1,
     143,    -1,    -1,    -1,    -1,    -1,   149,    -1,    -1,    -1,
     139,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,    -1,
    2080,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   394,
     395,   396,   397,   398,   399,   400,  2096,    -1,   403,    -1,
      -1,    -1,   185,   124,   409,   174,    -1,    -1,    -1,    -1,
     193,    -1,   181,  2105,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,   145,   405,   406,    -1,    -1,    -1,
      -1,    -1,    -1,   202,   155,    -1,    -1,    -1,    -1,    30,
      -1,    -1,   211,   212,   213,    -1,    -1,    -1,   231,    -1,
      -1,    -1,   235,    -1,    -1,   238,   239,    -1,   227,    -1,
      -1,    -1,  2154,    -1,    -1,    -1,   187,  2167,    -1,    -1,
      -1,    -1,  2164,    -1,  2164,   196,   197,   246,    -1,   262,
      -1,  2181,    -1,  2183,    -1,  2185,   255,    78,    79,    -1,
      -1,    -1,    -1,    -1,    -1,  2187,   217,    -1,    -1,    -1,
      91,    92,   271,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     101,    -1,    -1,   104,    -1,    -1,    -1,    -1,  2210,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   267,    -1,   139,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,  2261,    -1,    -1,    -1,    -1,  2266,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   343,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   174,    -1,    -1,    -1,   356,   309,    -1,
     181,    -1,    -1,    -1,    -1,    -1,    -1,  2289,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   202,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     211,   212,   213,    -1,    -1,    -1,  2318,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   404,   227,    -1,  2330,    -1,
    2340,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,  2341,
    2342,    -1,  2344,    -1,    -1,   246,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   255,    -1,    -1,     4,     5,     6,
       7,     8,    -1,   394,   395,   396,   397,   398,   399,   400,
     271,    -1,   403,  2375,   405,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    32,  2396,  2389,    35,    -1,
      37,    -1,    39,    40,    41,    42,    43,    -1,    -1,    46,
      -1,    48,    49,    50,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    -1,    -1,    62,    63,    64,    65,    66,
      67,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    82,    83,    84,    85,    86,
      -1,    88,   343,    90,    91,    92,    -1,    94,    -1,    -1,
      97,    -1,    99,    -1,   101,   356,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,   121,    -1,    -1,    -1,   125,    -1,
     127,    -1,   129,   130,    -1,    -1,   133,   134,    -1,   136,
     137,    -1,    -1,   140,    -1,    -1,   143,    -1,    -1,   146,
     147,    -1,    -1,    -1,   151,   152,   153,    -1,    -1,    -1,
     157,   158,   159,   160,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,   173,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
     187,   188,   189,   190,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,   215,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,   242,    -1,   244,   245,   246,
     247,   248,   249,   250,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,   271,   272,   273,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,   301,    -1,    -1,    -1,    -1,    -1,
     307,   308,    -1,   310,   311,   312,   313,   314,   315,   316,
     317,   318,   319,    -1,    -1,    -1,   323,   324,   325,   326,
      -1,   328,   329,   330,   331,   332,   333,   334,    -1,   336,
     337,    -1,    -1,   340,   341,   342,   343,   344,   345,   346,
     347,   348,   349,    -1,   351,   352,   353,   354,   355,   356,
     357,    -1,   359,   360,   361,   362,   363,   364,   365,   366,
     367,   368,   369,   370,   371,   372,   373,   374,   375,   376,
     377,    -1,   379,    -1,   381,   382,   383,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,    -1,    -1,   396,
      -1,    -1,    -1,    -1,   401,    -1,    -1,   404,    -1,    -1,
     407,   408,    -1,   410,   411,     4,     5,     6,     7,     8,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,
      29,    30,    31,    32,    -1,    -1,    35,    -1,    37,    -1,
      39,    40,    41,    42,    43,    -1,    -1,    46,    -1,    48,
      49,    50,    51,    -1,    -1,    54,    55,    56,    57,    58,
      59,    -1,    -1,    62,    63,    64,    65,    66,    67,    68,
      69,    -1,    -1,    72,    73,    74,    -1,    -1,    -1,    78,
      79,    80,    81,    82,    83,    84,    85,    -1,    -1,    88,
      -1,    90,    91,    92,    -1,    94,    -1,    -1,    97,    -1,
      99,    -1,   101,   102,    -1,   104,    -1,    -1,   107,   108,
      -1,   110,   111,    -1,    -1,   114,   115,    -1,   117,   118,
     119,   120,   121,    -1,    -1,    -1,   125,    -1,   127,    -1,
     129,   130,    -1,    -1,   133,   134,    -1,   136,   137,    -1,
      -1,   140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,
      -1,    -1,    -1,   152,   153,    -1,    -1,    -1,   157,   158,
     159,   160,    -1,    -1,   163,   164,   165,   166,   167,   168,
     169,    -1,   171,   172,   173,   174,   175,   176,   177,   178,
     179,   180,   181,   182,   183,    -1,   185,   186,   187,   188,
     189,   190,   191,   192,   193,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,
     209,   210,   211,   212,   213,    -1,   215,    -1,    -1,   218,
      -1,   220,    -1,   222,   223,    -1,    -1,   226,   227,   228,
      -1,   230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,
      -1,   240,    -1,   242,    -1,    -1,   245,   246,   247,   248,
     249,   250,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,
      -1,    -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,
      -1,    -1,   271,   272,   273,   274,   275,    -1,    -1,   278,
     279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   290,    -1,   292,    -1,   294,   295,   296,   297,    -1,
      -1,    -1,   301,    -1,    -1,    -1,    -1,    -1,   307,   308,
      -1,   310,   311,   312,   313,   314,   315,   316,   317,   318,
     319,    -1,    -1,    -1,   323,   324,   325,   326,    -1,   328,
     329,   330,   331,   332,   333,   334,    -1,   336,   337,    -1,
      -1,   340,   341,   342,   343,   344,   345,   346,   347,   348,
     349,    -1,   351,   352,   353,   354,   355,   356,   357,    -1,
     359,   360,   361,   362,   363,   364,   365,   366,   367,   368,
     369,   370,   371,   372,   373,   374,   375,   376,   377,    -1,
     379,    -1,   381,   382,   383,   384,    -1,    -1,   387,    -1,
     389,    -1,   391,   392,   393,    -1,    -1,   396,    -1,    -1,
      -1,    -1,   401,    -1,    -1,   404,    -1,    -1,   407,   408,
      -1,   410,   411,     4,     5,     6,     7,     8,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,    30,
      31,    32,    -1,    -1,    35,    -1,    37,    -1,    39,    40,
      41,    42,    43,    -1,    -1,    46,    -1,    48,    49,    50,
      51,    -1,    -1,    54,    55,    56,    57,    58,    59,    -1,
      -1,    62,    63,    64,    65,    66,    67,    68,    69,    -1,
      -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,
      81,    82,    83,    84,    85,    -1,    -1,    88,    -1,    90,
      91,    92,    -1,    94,    -1,    -1,    97,    -1,    99,    -1,
     101,   102,    -1,   104,    -1,    -1,   107,   108,    -1,   110,
     111,    -1,    -1,   114,   115,    -1,   117,   118,   119,   120,
     121,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,   130,
      -1,    -1,   133,   134,    -1,   136,   137,    -1,    -1,   140,
      -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,
      -1,   152,   153,    -1,    -1,    -1,   157,   158,   159,   160,
      -1,    -1,   163,   164,   165,   166,   167,   168,   169,    -1,
     171,   172,   173,   174,   175,   176,   177,   178,   179,   180,
     181,   182,   183,    -1,   185,   186,   187,   188,   189,   190,
     191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     201,   202,    -1,    -1,    -1,   206,   207,   208,   209,   210,
     211,   212,   213,    -1,   215,    -1,    -1,   218,    -1,   220,
      -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,   230,
     231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,
      -1,   242,    -1,    -1,   245,   246,   247,   248,   249,   250,
      -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,
      -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,
     271,   272,   273,   274,   275,    -1,    -1,   278,   279,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,
      -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,
     301,    -1,    -1,    -1,    -1,    -1,   307,   308,    -1,   310,
     311,   312,   313,   314,   315,   316,   317,   318,   319,    -1,
      -1,    -1,   323,   324,   325,   326,    -1,   328,   329,   330,
     331,   332,   333,   334,    -1,   336,   337,    -1,    -1,   340,
     341,   342,   343,   344,   345,   346,   347,   348,   349,    -1,
     351,   352,   353,   354,   355,   356,   357,    -1,   359,   360,
     361,   362,   363,   364,   365,   366,   367,   368,   369,   370,
     371,   372,   373,   374,   375,   376,   377,    -1,   379,    -1,
     381,   382,   383,   384,    -1,    -1,   387,    -1,   389,    -1,
     391,   392,   393,    -1,    -1,   396,    -1,    -1,    -1,    -1,
     401,    -1,    -1,   404,    -1,    -1,   407,   408,    -1,   410,
     411,     4,     5,     6,     7,     8,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    22,
      -1,    -1,    25,    26,    27,    -1,    29,    30,    31,    32,
      -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,    42,
      43,    -1,    -1,    46,    -1,    48,    49,    50,    51,    -1,
      -1,    54,    55,    56,    57,    58,    59,    -1,    -1,    62,
      63,    64,    65,    66,    67,    68,    69,    -1,    -1,    72,
      73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,    82,
      83,    84,    85,    -1,    -1,    88,    -1,    90,    91,    92,
      -1,    94,    -1,    -1,    97,    -1,    99,    -1,   101,    -1,
      -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,    -1,
      -1,   114,   115,    -1,   117,   118,   119,   120,   121,    -1,
      -1,    -1,   125,    -1,   127,    -1,   129,   130,    -1,    -1,
     133,   134,    -1,   136,   137,    -1,    -1,   140,    -1,    -1,
     143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,   152,
     153,    -1,    -1,    -1,   157,   158,   159,   160,    -1,    -1,
     163,   164,   165,   166,   167,   168,   169,    -1,   171,   172,
     173,   174,   175,   176,   177,   178,   179,   180,   181,   182,
     183,    -1,   185,   186,   187,   188,   189,   190,   191,    -1,
     193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,   202,
      -1,    -1,    -1,   206,   207,   208,   209,   210,   211,   212,
     213,    -1,   215,    -1,    -1,   218,    -1,   220,    -1,   222,
     223,    -1,    -1,   226,   227,   228,    -1,   230,   231,   232,
      -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,   242,
      -1,    -1,   245,   246,   247,   248,   249,   250,    -1,    -1,
     253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,   262,
      -1,    -1,    -1,   266,    -1,   268,    -1,    -1,   271,   272,
     273,   274,   275,    -1,    -1,   278,   279,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,   292,
      -1,   294,   295,   296,   297,    -1,    -1,    -1,   301,    -1,
      -1,    -1,    -1,    -1,   307,   308,    -1,   310,   311,   312,
     313,   314,   315,   316,   317,   318,   319,    -1,    -1,    -1,
     323,   324,   325,   326,    -1,   328,   329,   330,   331,   332,
     333,   334,    -1,   336,   337,    -1,    -1,   340,   341,   342,
     343,   344,   345,   346,   347,   348,   349,    -1,   351,   352,
     353,   354,   355,   356,   357,    -1,   359,   360,   361,   362,
     363,   364,   365,   366,   367,   368,   369,   370,   371,   372,
     373,   374,   375,   376,   377,    -1,   379,    -1,   381,   382,
     383,   384,    -1,    -1,   387,    -1,   389,    -1,   391,   392,
     393,    -1,    -1,   396,    -1,    -1,    -1,    -1,   401,    -1,
      -1,   404,   405,    -1,   407,   408,    -1,   410,   411,     4,
       5,     6,     7,     8,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    22,    -1,    -1,
      25,    26,    27,    -1,    29,    30,    31,    32,    -1,    -1,
      35,    -1,    37,    -1,    39,    40,    41,    42,    43,    -1,
      -1,    46,    -1,    48,    49,    50,    51,    -1,    -1,    54,
      55,    56,    57,    58,    59,    -1,    -1,    62,    63,    64,
      65,    66,    67,    68,    69,    -1,    -1,    72,    73,    -1,
      -1,    -1,    -1,    78,    79,    80,    81,    82,    83,    84,
      85,    -1,    -1,    88,    -1,    90,    91,    92,    -1,    94,
      -1,    -1,    97,    -1,    99,    -1,   101,    -1,    -1,   104,
      -1,    -1,   107,   108,    -1,   110,   111,    -1,    -1,   114,
     115,    -1,   117,   118,   119,   120,   121,    -1,    -1,    -1,
     125,    -1,   127,    -1,   129,   130,    -1,    -1,   133,   134,
      -1,   136,   137,    -1,    -1,   140,    -1,    -1,   143,    -1,
      -1,   146,   147,    -1,    -1,    -1,    -1,   152,   153,    -1,
      -1,    -1,   157,   158,   159,   160,    -1,    -1,   163,   164,
     165,   166,   167,   168,   169,    -1,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,    -1,
     185,   186,   187,   188,   189,   190,   191,    -1,   193,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   201,   202,    -1,    -1,
      -1,   206,   207,   208,   209,   210,   211,   212,   213,    -1,
     215,    -1,    -1,   218,    -1,   220,    -1,   222,   223,    -1,
      -1,   226,   227,   228,    -1,   230,   231,   232,    -1,    -1,
     235,    -1,   237,    -1,    -1,   240,    -1,   242,    -1,    -1,
     245,   246,   247,   248,   249,   250,    -1,    -1,   253,   254,
      -1,    -1,    -1,   258,    -1,    -1,    -1,   262,    -1,    -1,
      -1,   266,    -1,   268,    -1,    -1,   271,   272,   273,   274,
     275,    -1,    -1,   278,   279,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   290,    -1,   292,    -1,   294,
     295,   296,   297,    -1,    -1,    -1,   301,    -1,    -1,    -1,
      -1,    -1,   307,   308,    -1,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,    -1,    -1,    -1,   323,   324,
     325,   326,    -1,   328,   329,   330,   331,   332,   333,   334,
      -1,   336,   337,    -1,    -1,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,    -1,   351,   352,   353,   354,
     355,   356,   357,    -1,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,    -1,   379,    -1,   381,   382,   383,   384,
      -1,    -1,   387,    -1,   389,    -1,   391,   392,   393,    -1,
      -1,   396,    -1,    -1,    -1,    -1,   401,    -1,    -1,   404,
     405,    -1,   407,   408,    -1,   410,   411,     4,     5,     6,
       7,     8,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    32,    -1,    -1,    35,    -1,
      37,    -1,    39,    40,    41,    42,    43,    -1,    -1,    46,
      -1,    48,    49,    50,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    -1,    -1,    62,    63,    64,    65,    66,
      67,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    82,    83,    84,    85,    -1,
      -1,    88,    -1,    90,    91,    92,    -1,    94,    -1,    -1,
      97,    -1,    99,    -1,   101,    -1,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,   121,    -1,    -1,    -1,   125,    -1,
     127,    -1,   129,   130,    -1,    -1,   133,   134,    -1,   136,
     137,    -1,    -1,   140,    -1,    -1,   143,    -1,    -1,   146,
     147,    -1,    -1,    -1,    -1,   152,   153,    -1,    -1,    -1,
     157,   158,   159,   160,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,   173,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
     187,   188,   189,   190,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,   215,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,   242,    -1,    -1,   245,   246,
     247,   248,   249,   250,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,   271,   272,   273,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,   301,    -1,    -1,    -1,    -1,    -1,
     307,   308,    -1,   310,   311,   312,   313,   314,   315,   316,
     317,   318,   319,    -1,    -1,    -1,   323,   324,   325,   326,
      -1,   328,   329,   330,   331,   332,   333,   334,    -1,   336,
     337,    -1,    -1,   340,   341,   342,   343,   344,   345,   346,
     347,   348,   349,    -1,   351,   352,   353,   354,   355,   356,
     357,    -1,   359,   360,   361,   362,   363,   364,   365,   366,
     367,   368,   369,   370,   371,   372,   373,   374,   375,   376,
     377,    -1,   379,    -1,   381,   382,   383,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,    -1,    -1,   396,
      -1,    -1,    -1,    -1,   401,    -1,    -1,   404,   405,    -1,
     407,   408,    -1,   410,   411,     4,     5,     6,     7,     8,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,
      29,    30,    31,    32,    -1,    -1,    35,    -1,    37,    -1,
      39,    40,    41,    42,    43,    -1,    -1,    46,    -1,    48,
      49,    50,    51,    -1,    -1,    54,    55,    56,    57,    58,
      59,    -1,    -1,    62,    63,    64,    65,    66,    67,    68,
      69,    -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,
      79,    80,    81,    82,    83,    84,    85,    -1,    -1,    88,
      -1,    90,    91,    92,    -1,    94,    -1,    -1,    97,    -1,
      99,    -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,
      -1,   110,   111,    -1,    -1,   114,   115,    -1,   117,   118,
     119,   120,   121,    -1,    -1,    -1,   125,    -1,   127,    -1,
     129,   130,    -1,    -1,   133,   134,    -1,   136,   137,    -1,
      -1,   140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,
      -1,    -1,    -1,   152,   153,    -1,    -1,    -1,   157,   158,
     159,   160,    -1,    -1,   163,   164,   165,   166,   167,   168,
     169,    -1,   171,   172,   173,   174,   175,   176,   177,   178,
     179,   180,   181,   182,   183,    -1,   185,   186,   187,   188,
     189,   190,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,
     209,   210,   211,   212,   213,    -1,   215,    -1,    -1,   218,
      -1,   220,    -1,   222,   223,    -1,    -1,   226,   227,   228,
      -1,   230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,
      -1,   240,    -1,   242,    -1,    -1,   245,   246,   247,   248,
     249,   250,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,
      -1,    -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,
      -1,    -1,   271,   272,   273,   274,   275,    -1,    -1,   278,
     279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   290,    -1,   292,    -1,   294,   295,   296,   297,    -1,
      -1,    -1,   301,    -1,    -1,    -1,    -1,    -1,   307,   308,
      -1,   310,   311,   312,   313,   314,   315,   316,   317,   318,
     319,    -1,    -1,    -1,   323,   324,   325,   326,    -1,   328,
     329,   330,   331,   332,   333,   334,    -1,   336,   337,    -1,
      -1,   340,   341,   342,   343,   344,   345,   346,   347,   348,
     349,    -1,   351,   352,   353,   354,   355,   356,   357,    -1,
     359,   360,   361,   362,   363,   364,   365,   366,   367,   368,
     369,   370,   371,   372,   373,   374,   375,   376,   377,    -1,
     379,    -1,   381,   382,   383,   384,    -1,    -1,   387,    -1,
     389,    -1,   391,   392,   393,    -1,    -1,   396,    -1,    -1,
      -1,    -1,   401,    -1,    -1,   404,   405,    -1,   407,   408,
      -1,   410,   411,     4,     5,     6,     7,     8,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,    30,
      31,    32,    -1,    -1,    35,    -1,    37,    -1,    39,    40,
      41,    42,    43,    -1,    -1,    46,    -1,    48,    49,    50,
      51,    -1,    -1,    54,    55,    56,    57,    58,    59,    -1,
      -1,    62,    63,    64,    65,    66,    67,    68,    69,    -1,
      -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,
      81,    82,    83,    84,    85,    -1,    -1,    88,    -1,    90,
      91,    92,    -1,    94,    -1,    -1,    97,    -1,    99,    -1,
     101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,
     111,    -1,    -1,   114,   115,    -1,   117,   118,   119,   120,
     121,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,   130,
      -1,    -1,   133,   134,    -1,   136,   137,    -1,    -1,   140,
      -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,
      -1,   152,   153,    -1,    -1,    -1,   157,   158,   159,   160,
      -1,    -1,   163,   164,   165,   166,   167,   168,   169,    -1,
     171,   172,   173,   174,   175,   176,   177,   178,   179,   180,
     181,   182,   183,    -1,   185,   186,   187,   188,   189,   190,
     191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     201,   202,    -1,    -1,    -1,   206,   207,   208,   209,   210,
     211,   212,   213,    -1,   215,    -1,    -1,   218,    -1,   220,
      -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,   230,
     231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,
      -1,   242,    -1,    -1,   245,   246,   247,   248,   249,   250,
      -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,
      -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,
     271,   272,   273,   274,   275,    -1,    -1,   278,   279,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,
      -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,
     301,    -1,    -1,    -1,    -1,    -1,   307,   308,    -1,   310,
     311,   312,   313,   314,   315,   316,   317,   318,   319,    -1,
      -1,    -1,   323,   324,   325,   326,    -1,   328,   329,   330,
     331,   332,   333,   334,    -1,   336,   337,    -1,    -1,   340,
     341,   342,   343,   344,   345,   346,   347,   348,   349,    -1,
     351,   352,   353,   354,   355,   356,   357,    -1,   359,   360,
     361,   362,   363,   364,   365,   366,   367,   368,   369,   370,
     371,   372,   373,   374,   375,   376,   377,    -1,   379,    -1,
     381,   382,   383,   384,    -1,    -1,   387,    -1,   389,    -1,
     391,   392,   393,    -1,    -1,   396,    -1,    -1,    -1,    -1,
     401,    -1,    -1,   404,    -1,    -1,   407,   408,    -1,   410,
     411,     4,     5,     6,     7,     8,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    22,
      -1,    -1,    25,    26,    27,    -1,    29,    30,    31,    32,
      -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,    42,
      43,    -1,    -1,    46,    -1,    48,    49,    50,    51,    -1,
      -1,    54,    55,    56,    57,    58,    59,    -1,    -1,    62,
      63,    64,    65,    66,    67,    68,    69,    -1,    -1,    72,
      73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,    82,
      83,    84,    85,    -1,    -1,    88,    -1,    90,    91,    92,
      -1,    94,    -1,    -1,    97,    -1,    99,    -1,   101,    -1,
      -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,    -1,
      -1,   114,   115,    -1,   117,   118,   119,   120,   121,    -1,
      -1,    -1,   125,    -1,   127,    -1,   129,   130,    -1,    -1,
     133,   134,    -1,   136,   137,    -1,    -1,   140,    -1,    -1,
     143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,   152,
     153,    -1,    -1,    -1,   157,   158,   159,   160,    -1,    -1,
     163,   164,   165,   166,   167,   168,   169,    -1,   171,   172,
     173,   174,   175,   176,   177,   178,   179,   180,   181,   182,
     183,    -1,   185,   186,   187,   188,   189,   190,   191,    -1,
     193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,   202,
      -1,    -1,    -1,   206,   207,   208,   209,   210,   211,   212,
     213,    -1,   215,    -1,    -1,   218,    -1,   220,    -1,   222,
     223,    -1,    -1,   226,   227,   228,    -1,   230,   231,   232,
      -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,   242,
      -1,    -1,   245,   246,   247,   248,   249,   250,    -1,    -1,
     253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,   262,
      -1,    -1,    -1,   266,    -1,   268,    -1,    -1,   271,   272,
     273,   274,   275,    -1,    -1,   278,   279,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,   292,
      -1,   294,   295,   296,   297,    -1,    -1,    -1,   301,    -1,
      -1,    -1,    -1,    -1,   307,   308,    -1,   310,   311,   312,
     313,   314,   315,   316,   317,   318,   319,    -1,    -1,    -1,
     323,   324,   325,   326,    -1,   328,   329,   330,   331,   332,
     333,   334,    -1,   336,   337,    -1,    -1,   340,   341,   342,
     343,   344,   345,   346,   347,   348,   349,    -1,   351,   352,
     353,   354,   355,   356,   357,    -1,   359,   360,   361,   362,
     363,   364,   365,   366,   367,   368,   369,   370,   371,   372,
     373,   374,   375,   376,   377,    -1,   379,    -1,   381,   382,
     383,   384,    -1,    -1,   387,    -1,   389,    -1,   391,   392,
     393,    -1,    -1,   396,    -1,    -1,    -1,    -1,   401,    -1,
      -1,   404,    -1,    -1,   407,   408,    -1,   410,   411,     4,
       5,     6,     7,     8,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    22,    -1,    -1,
      25,    26,    27,    -1,    29,    30,    31,    32,    -1,    -1,
      35,    -1,    37,    -1,    39,    40,    41,    42,    43,    -1,
      -1,    46,    -1,    48,    49,    50,    51,    -1,    -1,    54,
      55,    56,    57,    58,    59,    -1,    -1,    62,    63,    64,
      65,    66,    67,    68,    69,    -1,    -1,    72,    73,    -1,
      -1,    -1,    -1,    78,    79,    80,    81,    82,    83,    84,
      85,    -1,    -1,    88,    -1,    90,    91,    92,    -1,    94,
      -1,    -1,    97,    -1,    99,    -1,   101,    -1,    -1,   104,
      -1,    -1,   107,   108,    -1,   110,   111,    -1,    -1,   114,
     115,    -1,   117,   118,   119,   120,   121,    -1,    -1,    -1,
     125,    -1,   127,    -1,   129,   130,    -1,    -1,   133,   134,
      -1,   136,   137,    -1,    -1,   140,    -1,    -1,   143,    -1,
      -1,   146,   147,    -1,    -1,    -1,    -1,   152,   153,    -1,
      -1,    -1,   157,   158,   159,   160,    -1,    -1,   163,   164,
     165,   166,   167,   168,   169,    -1,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,    -1,
     185,   186,   187,   188,   189,   190,   191,    -1,   193,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   201,   202,    -1,    -1,
      -1,   206,   207,   208,   209,   210,   211,   212,   213,    -1,
     215,    -1,    -1,   218,    -1,   220,    -1,   222,   223,    -1,
      -1,   226,   227,   228,    -1,   230,   231,   232,    -1,    -1,
     235,    -1,   237,    -1,    -1,   240,    -1,   242,    -1,    -1,
     245,   246,   247,   248,   249,   250,    -1,    -1,   253,   254,
      -1,    -1,    -1,   258,    -1,    -1,    -1,   262,    -1,    -1,
      -1,   266,    -1,   268,    -1,    -1,   271,   272,   273,   274,
     275,    -1,    -1,   278,   279,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   290,    -1,   292,    -1,   294,
     295,   296,   297,    -1,    -1,    -1,   301,    -1,    -1,    -1,
      -1,    -1,   307,   308,    -1,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,    -1,    -1,    -1,   323,   324,
     325,   326,    -1,   328,   329,   330,   331,   332,   333,   334,
      -1,   336,   337,    -1,    -1,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,    -1,   351,   352,   353,   354,
     355,   356,   357,    -1,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,    -1,   379,    -1,   381,   382,   383,   384,
      -1,    -1,   387,    -1,   389,    -1,   391,   392,   393,    -1,
      -1,   396,    -1,    -1,    -1,    -1,   401,    -1,    -1,   404,
      -1,    -1,   407,   408,    -1,   410,   411,     4,     5,     6,
       7,     8,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    32,    -1,    -1,    35,    -1,
      37,    -1,    39,    40,    41,    42,    43,    -1,    -1,    46,
      -1,    48,    49,    50,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    -1,    -1,    62,    63,    64,    65,    66,
      67,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    82,    83,    84,    85,    -1,
      -1,    88,    -1,    90,    91,    92,    -1,    94,    -1,    -1,
      97,    -1,    99,    -1,   101,    -1,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,   121,    -1,    -1,    -1,   125,    -1,
     127,    -1,   129,   130,    -1,    -1,   133,   134,    -1,   136,
     137,    -1,    -1,   140,    -1,    -1,   143,    -1,    -1,   146,
     147,    -1,    -1,    -1,    -1,   152,   153,    -1,    -1,    -1,
     157,   158,   159,   160,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,   173,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
     187,   188,   189,   190,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,   215,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,   242,    -1,    -1,   245,   246,
     247,   248,   249,   250,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,   271,   272,   273,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,   301,    -1,    -1,    -1,    -1,    -1,
     307,   308,    -1,   310,   311,   312,   313,   314,   315,   316,
     317,   318,   319,    -1,    -1,    -1,   323,   324,   325,   326,
      -1,   328,   329,   330,   331,   332,   333,   334,    -1,   336,
     337,    -1,    -1,   340,   341,   342,   343,   344,   345,   346,
     347,   348,   349,    -1,   351,   352,   353,   354,   355,   356,
     357,    -1,   359,   360,   361,   362,   363,   364,   365,   366,
     367,   368,   369,   370,   371,   372,   373,   374,   375,   376,
     377,    -1,   379,    -1,   381,   382,   383,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,    -1,    -1,   396,
      -1,    -1,    -1,    -1,   401,    -1,    -1,   404,    -1,    -1,
     407,   408,    -1,   410,   411,     4,     5,     6,     7,     8,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,
      29,    30,    31,    32,    -1,    -1,    35,    -1,    37,    -1,
      39,    40,    41,    42,    43,    -1,    -1,    46,    -1,    48,
      49,    50,    51,    -1,    -1,    54,    55,    56,    57,    58,
      59,    -1,    -1,    62,    63,    64,    65,    66,    67,    68,
      69,    -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,
      79,    80,    81,    82,    83,    84,    85,    -1,    -1,    88,
      -1,    90,    91,    92,    -1,    94,    -1,    -1,    97,    -1,
      99,    -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,
      -1,   110,   111,    -1,    -1,   114,   115,    -1,   117,   118,
     119,   120,   121,    -1,    -1,    -1,   125,    -1,   127,    -1,
     129,   130,    -1,    -1,   133,   134,    -1,   136,   137,    -1,
      -1,   140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,
      -1,    -1,    -1,   152,   153,    -1,    -1,    -1,   157,   158,
     159,   160,    -1,    -1,   163,   164,   165,   166,   167,   168,
     169,    -1,   171,   172,   173,   174,   175,   176,   177,   178,
     179,   180,   181,   182,   183,    -1,   185,   186,   187,   188,
     189,   190,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,
     209,   210,   211,   212,   213,    -1,   215,    -1,    -1,   218,
      -1,   220,    -1,   222,   223,    -1,    -1,   226,   227,   228,
      -1,   230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,
      -1,   240,    -1,   242,    -1,    -1,   245,   246,   247,   248,
     249,   250,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,
      -1,    -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,
      -1,    -1,   271,   272,   273,   274,   275,    -1,    -1,   278,
     279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   290,    -1,   292,    -1,   294,   295,   296,   297,    -1,
      -1,    -1,   301,    -1,    -1,    -1,    -1,    -1,   307,   308,
      -1,   310,   311,   312,   313,   314,   315,   316,   317,   318,
     319,    -1,    -1,    -1,   323,   324,   325,   326,    -1,   328,
     329,   330,   331,   332,   333,   334,    -1,   336,   337,    -1,
      -1,   340,   341,   342,   343,   344,   345,   346,   347,   348,
     349,    -1,   351,   352,   353,   354,   355,   356,   357,    -1,
     359,   360,   361,   362,   363,   364,   365,   366,   367,   368,
     369,   370,   371,   372,   373,   374,   375,   376,   377,    -1,
     379,    -1,   381,   382,   383,   384,    -1,    -1,   387,    -1,
     389,    -1,   391,   392,   393,    -1,    -1,   396,    -1,    -1,
      -1,    -1,   401,    -1,    -1,   404,    -1,    -1,   407,   408,
      -1,   410,   411,     4,     5,     6,     7,     8,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,    30,
      31,    32,    -1,    -1,    35,    -1,    37,    -1,    39,    40,
      41,    42,    43,    -1,    -1,    46,    -1,    48,    49,    50,
      51,    -1,    -1,    54,    55,    56,    57,    58,    59,    -1,
      -1,    62,    63,    64,    65,    66,    67,    68,    69,    -1,
      -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,
      81,    82,    83,    84,    85,    -1,    -1,    88,    -1,    90,
      91,    92,    -1,    94,    -1,    -1,    97,    -1,    99,    -1,
     101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,
     111,    -1,    -1,   114,   115,    -1,   117,   118,   119,   120,
     121,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,   130,
      -1,    -1,   133,   134,    -1,   136,   137,    -1,    -1,   140,
      -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,
      -1,   152,   153,    -1,    -1,    -1,   157,   158,   159,   160,
      -1,    -1,   163,   164,   165,   166,   167,   168,   169,    -1,
     171,   172,   173,   174,   175,   176,   177,   178,   179,   180,
     181,   182,   183,    -1,   185,   186,   187,   188,   189,   190,
     191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     201,   202,    -1,    -1,    -1,   206,   207,   208,   209,   210,
     211,   212,   213,    -1,   215,    -1,    -1,   218,    -1,   220,
      -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,   230,
     231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,
      -1,   242,    -1,    -1,   245,   246,   247,   248,   249,   250,
      -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,
      -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,
     271,   272,   273,   274,   275,    -1,    -1,   278,   279,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,
      -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,
     301,    -1,    -1,    -1,    -1,    -1,   307,   308,    -1,   310,
     311,   312,   313,   314,   315,   316,   317,   318,   319,    -1,
      -1,    -1,   323,   324,   325,   326,    -1,   328,   329,   330,
     331,   332,   333,   334,    -1,   336,   337,    -1,    -1,   340,
     341,   342,   343,   344,   345,   346,   347,   348,   349,    -1,
     351,   352,   353,   354,   355,   356,   357,    -1,   359,   360,
     361,   362,   363,   364,   365,   366,   367,   368,   369,   370,
     371,   372,   373,   374,   375,   376,   377,    -1,   379,    -1,
     381,   382,   383,   384,    -1,    -1,   387,    -1,   389,    -1,
     391,   392,   393,    -1,    -1,   396,    -1,    -1,    -1,    -1,
     401,    -1,    -1,   404,    -1,    -1,   407,   408,    -1,   410,
     411,     4,     5,     6,     7,     8,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    22,
      -1,    -1,    25,    26,    27,    -1,    29,    30,    31,    32,
      -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,    42,
      43,    -1,    -1,    46,    -1,    48,    49,    50,    51,    -1,
      -1,    54,    55,    56,    57,    58,    59,    -1,    -1,    62,
      63,    64,    65,    66,    67,    68,    69,    -1,    -1,    72,
      73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,    82,
      83,    84,    85,    -1,    -1,    88,    -1,    90,    91,    92,
      -1,    94,    -1,    -1,    97,    -1,    99,    -1,   101,    -1,
      -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,    -1,
      -1,   114,   115,    -1,   117,   118,   119,   120,   121,    -1,
      -1,    -1,   125,    -1,   127,    -1,   129,   130,    -1,    -1,
     133,   134,    -1,   136,   137,    -1,    -1,   140,    -1,    -1,
     143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,   152,
     153,    -1,    -1,    -1,   157,   158,   159,   160,    -1,    -1,
     163,   164,   165,   166,   167,   168,   169,    -1,   171,   172,
     173,   174,   175,   176,   177,   178,   179,   180,   181,   182,
     183,    -1,   185,   186,   187,   188,   189,   190,   191,    -1,
     193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,   202,
      -1,    -1,    -1,   206,   207,   208,   209,   210,   211,   212,
     213,    -1,   215,    -1,    -1,   218,    -1,   220,    -1,   222,
     223,    -1,    -1,   226,   227,   228,    -1,   230,   231,   232,
      -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,   242,
      -1,    -1,   245,   246,   247,   248,   249,   250,    -1,    -1,
     253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,   262,
      -1,    -1,    -1,   266,    -1,   268,    -1,    -1,   271,   272,
     273,   274,   275,    -1,    -1,   278,   279,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,   292,
      -1,   294,   295,   296,   297,    -1,    -1,    -1,   301,    -1,
      -1,    -1,    -1,    -1,   307,   308,    -1,   310,   311,   312,
     313,   314,   315,   316,   317,   318,   319,    -1,    -1,    -1,
     323,   324,   325,   326,    -1,   328,   329,   330,   331,   332,
     333,   334,    -1,   336,   337,    -1,    -1,   340,   341,   342,
     343,   344,   345,   346,   347,   348,   349,    -1,   351,   352,
     353,   354,   355,   356,   357,    -1,   359,   360,   361,   362,
     363,   364,   365,   366,   367,   368,   369,   370,   371,   372,
     373,   374,   375,   376,   377,    -1,   379,    -1,   381,   382,
     383,   384,    -1,    -1,   387,    -1,   389,    -1,   391,   392,
     393,    -1,    -1,   396,    -1,    -1,    -1,    -1,   401,    -1,
      -1,   404,    -1,    -1,   407,   408,    -1,   410,   411,     4,
       5,     6,     7,     8,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    22,    -1,    -1,
      25,    26,    27,    -1,    29,    30,    31,    32,    -1,    -1,
      35,    -1,    37,    -1,    39,    40,    41,    42,    43,    -1,
      -1,    46,    -1,    48,    49,    50,    51,    -1,    -1,    54,
      55,    56,    57,    58,    59,    -1,    -1,    62,    63,    64,
      65,    66,    67,    68,    69,    -1,    -1,    72,    73,    -1,
      -1,    -1,    -1,    78,    79,    80,    81,    82,    83,    84,
      85,    -1,    -1,    88,    -1,    90,    91,    92,    -1,    94,
      -1,    -1,    97,    -1,    99,    -1,   101,    -1,    -1,   104,
      -1,    -1,   107,   108,    -1,   110,   111,    -1,    -1,   114,
     115,    -1,   117,   118,   119,   120,   121,    -1,    -1,    -1,
     125,    -1,   127,    -1,   129,   130,    -1,    -1,   133,   134,
      -1,   136,   137,    -1,    -1,   140,    -1,    -1,   143,    -1,
      -1,   146,   147,    -1,    -1,    -1,    -1,   152,   153,    -1,
      -1,    -1,   157,   158,   159,   160,    -1,    -1,   163,   164,
     165,   166,   167,   168,   169,    -1,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,    -1,
     185,   186,   187,   188,   189,   190,   191,    -1,   193,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   201,   202,    -1,    -1,
      -1,   206,   207,   208,   209,   210,   211,   212,   213,    -1,
     215,    -1,    -1,   218,    -1,   220,    -1,   222,   223,    -1,
      -1,   226,   227,   228,    -1,   230,   231,   232,    -1,    -1,
     235,    -1,   237,    -1,    -1,   240,    -1,   242,    -1,    -1,
     245,   246,   247,   248,   249,   250,    -1,    -1,   253,   254,
      -1,    -1,    -1,   258,    -1,    -1,    -1,   262,    -1,    -1,
      -1,   266,    -1,   268,    -1,    -1,   271,   272,   273,   274,
     275,    -1,    -1,   278,   279,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   290,    -1,   292,    -1,   294,
     295,   296,   297,    -1,    -1,    -1,   301,    -1,    -1,    -1,
      -1,    -1,   307,   308,    -1,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,    -1,    -1,    -1,   323,   324,
     325,   326,    -1,   328,   329,   330,   331,   332,   333,   334,
      -1,   336,   337,    -1,    -1,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,    -1,   351,   352,   353,   354,
     355,   356,   357,    -1,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,    -1,   379,    -1,   381,   382,   383,   384,
      -1,    -1,   387,    -1,   389,    -1,   391,   392,   393,    -1,
      -1,   396,    -1,    -1,    -1,    -1,   401,    -1,    -1,   404,
      -1,    -1,   407,   408,    -1,   410,   411,     4,     5,     6,
       7,     8,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    -1,    -1,    -1,    35,    -1,
      37,    -1,    39,    40,    41,    -1,    43,    -1,    -1,    46,
      -1,    48,    -1,    -1,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    60,    -1,    62,    63,    64,    -1,    66,
      -1,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    -1,    83,    84,    85,    -1,
      -1,    88,    -1,    -1,    91,    92,    -1,    94,    -1,    -1,
      97,    98,    -1,    -1,   101,    -1,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,    -1,    -1,    -1,    -1,   125,   126,
     127,    -1,   129,    -1,    -1,    -1,   133,    -1,    -1,   136,
     137,    -1,   139,   140,    -1,    -1,   143,    -1,    -1,   146,
     147,    -1,    -1,   150,    -1,    -1,   153,    -1,    -1,    -1,
     157,    -1,   159,    -1,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,    -1,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
      -1,   188,    -1,    -1,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,    -1,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,    -1,    -1,    -1,   245,   246,
      -1,    -1,    -1,    -1,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,    -1,   272,    -1,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     307,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   323,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   340,   341,    -1,   343,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   351,   352,   353,   354,    -1,   356,
      -1,    -1,    -1,    -1,    -1,    -1,   363,   364,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   379,    -1,   381,    -1,    -1,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,     4,     5,     6,
       7,     8,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   411,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    -1,    -1,    -1,    35,    -1,
      37,    -1,    39,    40,    41,    -1,    43,    -1,    -1,    46,
      -1,    48,    -1,    -1,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    -1,    -1,    62,    63,    64,    -1,    66,
      -1,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    -1,    83,    84,    85,    -1,
      -1,    88,    -1,    -1,    91,    92,    -1,    94,    -1,    -1,
      97,    98,    -1,    -1,   101,    -1,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,    -1,    -1,    -1,    -1,   125,   126,
     127,    -1,   129,    -1,    -1,    -1,   133,    -1,    -1,   136,
     137,    -1,   139,   140,    -1,    -1,   143,    -1,    -1,   146,
     147,    -1,    -1,   150,    -1,    -1,   153,    -1,    -1,    -1,
     157,    -1,   159,    -1,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,    -1,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
      -1,   188,    -1,    -1,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,    -1,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,    -1,    -1,    -1,   245,   246,
      -1,    -1,    -1,    -1,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,    -1,   272,    -1,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     307,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   323,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   340,   341,    -1,   343,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   351,   352,   353,   354,    -1,   356,
      -1,    -1,    -1,    -1,    -1,    -1,   363,   364,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   379,    -1,   381,    -1,    -1,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,     4,     5,     6,
       7,     8,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   411,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    -1,    -1,    -1,    35,    -1,
      37,    -1,    39,    40,    41,    -1,    43,    -1,    -1,    46,
      -1,    48,    -1,    -1,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    60,    -1,    62,    63,    64,    -1,    66,
      -1,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    -1,    83,    84,    85,    -1,
      -1,    88,    -1,    -1,    91,    92,    -1,    94,    -1,    -1,
      97,    -1,    -1,    -1,   101,    -1,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,    -1,    -1,    -1,    -1,   125,    -1,
     127,    -1,   129,    -1,    -1,    -1,   133,    -1,    -1,   136,
     137,    -1,    -1,   140,    -1,    -1,   143,    -1,    -1,   146,
     147,    -1,    -1,    -1,    -1,    -1,   153,    -1,    -1,    -1,
     157,    -1,   159,    -1,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,    -1,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
      -1,   188,    -1,    -1,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,    -1,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,    -1,    -1,    -1,   245,   246,
      -1,    -1,    -1,    -1,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,    -1,   272,    -1,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     307,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   323,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   340,   341,    -1,   343,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   351,   352,   353,   354,    -1,   356,
      -1,    -1,    -1,    -1,    -1,    -1,   363,   364,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   379,    -1,   381,    -1,    -1,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,     4,     5,     6,
       7,     8,    -1,    -1,    -1,    -1,    -1,   404,    -1,    -1,
      -1,    -1,    -1,    -1,   411,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    -1,    -1,    -1,    35,    -1,
      37,    -1,    39,    40,    41,    -1,    43,    -1,    -1,    46,
      -1,    48,    -1,    -1,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    60,    -1,    62,    63,    64,    -1,    66,
      -1,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    -1,    83,    84,    85,    -1,
      -1,    88,    -1,    -1,    91,    92,    -1,    94,    -1,    -1,
      97,    -1,    -1,    -1,   101,    -1,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,    -1,    -1,    -1,    -1,   125,    -1,
     127,    -1,   129,    -1,    -1,    -1,   133,    -1,    -1,   136,
     137,    -1,    -1,   140,    -1,    -1,   143,    -1,    -1,   146,
     147,    -1,    -1,    -1,    -1,    -1,   153,    -1,    -1,    -1,
     157,    -1,   159,    -1,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,    -1,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
      -1,   188,    -1,    -1,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,    -1,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,    -1,    -1,    -1,   245,   246,
      -1,    -1,    -1,    -1,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,    -1,   272,    -1,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     307,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   323,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   340,   341,    -1,   343,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   351,   352,   353,   354,    -1,   356,
      -1,    -1,    -1,    -1,    -1,    -1,   363,   364,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   379,    -1,   381,    -1,    -1,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,     4,     5,     6,
       7,     8,    -1,    -1,    -1,    -1,    -1,    -1,   405,    -1,
      -1,    -1,    -1,    -1,   411,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    -1,    -1,    -1,    35,    -1,
      37,    -1,    39,    40,    41,    -1,    43,    -1,    -1,    46,
      -1,    48,    -1,    -1,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    -1,    -1,    62,    63,    64,    -1,    66,
      -1,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    -1,    83,    84,    85,    -1,
      -1,    88,    -1,    -1,    91,    92,    -1,    94,    -1,    -1,
      97,    -1,    -1,    -1,   101,    -1,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,    -1,    -1,    -1,    -1,   125,    -1,
     127,    -1,   129,    -1,    -1,    -1,   133,    -1,    -1,   136,
     137,    -1,    -1,   140,    -1,    -1,   143,   144,    -1,   146,
     147,    -1,    -1,    -1,    -1,    -1,   153,    -1,    -1,    -1,
     157,    -1,   159,    -1,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,    -1,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
      -1,   188,    -1,    -1,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,    -1,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,    -1,    -1,    -1,   245,   246,
      -1,    -1,    -1,    -1,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,    -1,   272,    -1,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     307,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   323,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   340,   341,    -1,   343,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   351,   352,   353,   354,    -1,   356,
      -1,    -1,    -1,    -1,    -1,    -1,   363,   364,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   379,    -1,   381,    -1,    -1,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,     4,     5,     6,
       7,     8,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   411,    22,    -1,    -1,    25,    26,
      27,    -1,    29,    30,    31,    -1,    -1,    -1,    35,    -1,
      37,    -1,    39,    40,    41,    -1,    43,    -1,    -1,    46,
      -1,    48,    -1,    -1,    51,    -1,    -1,    54,    55,    56,
      57,    58,    59,    -1,    -1,    62,    63,    64,    -1,    66,
      -1,    68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,
      -1,    78,    79,    80,    81,    -1,    83,    84,    85,    -1,
      -1,    88,    -1,    -1,    91,    92,    -1,    94,    -1,    -1,
      97,    -1,    -1,    -1,   101,    -1,    -1,   104,    -1,    -1,
     107,   108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,
     117,   118,   119,   120,    -1,    -1,    -1,    -1,   125,    -1,
     127,    -1,   129,    -1,    -1,    -1,   133,    -1,    -1,   136,
     137,    -1,    -1,   140,    -1,    -1,   143,    -1,    -1,   146,
     147,    -1,    -1,    -1,    -1,    -1,   153,    -1,    -1,    -1,
     157,    -1,   159,    -1,    -1,    -1,   163,   164,   165,   166,
     167,   168,   169,    -1,   171,   172,    -1,   174,   175,   176,
     177,   178,   179,   180,   181,   182,   183,    -1,   185,   186,
      -1,   188,    -1,    -1,   191,    -1,   193,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,
     207,   208,   209,   210,   211,   212,   213,    -1,    -1,    -1,
      -1,   218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,
     227,   228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,
     237,    -1,    -1,   240,    -1,    -1,    -1,    -1,   245,   246,
      -1,    -1,    -1,    -1,    -1,    -1,   253,   254,    -1,    -1,
      -1,   258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,
      -1,   268,    -1,    -1,    -1,   272,    -1,   274,   275,    -1,
      -1,   278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,
     297,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     307,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   323,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   340,   341,    -1,   343,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   351,   352,   353,   354,    -1,   356,
      -1,    -1,    -1,    -1,    -1,    -1,   363,   364,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   379,    -1,   381,    -1,    -1,   384,    -1,    -1,
     387,    -1,   389,    -1,   391,   392,   393,    -1,    -1,    -1,
      -1,   398,     4,     5,     6,     7,     8,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   411,    -1,    -1,    -1,    -1,    -1,
      22,    -1,    -1,    25,    26,    27,    -1,    29,    30,    31,
      -1,    -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,
      -1,    43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,
      -1,    -1,    54,    55,    56,    57,    58,    59,    -1,    -1,
      62,    63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,
      72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      -1,    83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,
      92,    -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,
      -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,
      -1,    -1,   114,   115,    -1,   117,   118,   119,   120,    -1,
      -1,    -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,
      -1,   133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,
      -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,
      -1,   153,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,
      -1,   163,   164,   165,   166,   167,   168,   169,    -1,   171,
     172,    -1,   174,   175,   176,   177,   178,   179,   180,   181,
     182,   183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,
      -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,
     202,    -1,    -1,    -1,   206,   207,   208,   209,   210,   211,
     212,   213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,
     222,   223,    -1,    -1,   226,   227,   228,    -1,   230,   231,
     232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,
      -1,    -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,
      -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,
     272,    -1,   274,   275,    -1,    -1,   278,   279,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,
      -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   351,
     352,   353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,    -1,   381,
      -1,    -1,   384,    -1,    -1,   387,    -1,   389,    -1,   391,
     392,   393,     4,     5,     6,     7,     8,    -1,    -1,    -1,
      -1,    -1,   404,    -1,    -1,    -1,    -1,    -1,    -1,   411,
      22,    -1,    -1,    25,    26,    27,    -1,    29,    30,    31,
      -1,    -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,
      -1,    43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,
      -1,    -1,    54,    55,    56,    57,    58,    59,    -1,    -1,
      62,    63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,
      72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      -1,    83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,
      92,    -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,
      -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,
      -1,    -1,   114,   115,    -1,   117,   118,   119,   120,    -1,
      -1,    -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,
      -1,   133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,
      -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,
      -1,   153,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,
      -1,   163,   164,   165,   166,   167,   168,   169,    -1,   171,
     172,    -1,   174,   175,   176,   177,   178,   179,   180,   181,
     182,   183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,
      -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,
     202,    -1,    -1,    -1,   206,   207,   208,   209,   210,   211,
     212,   213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,
     222,   223,    -1,    -1,   226,   227,   228,    -1,   230,   231,
     232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,
      -1,    -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,
      -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,
     272,    -1,   274,   275,    -1,    -1,   278,   279,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,
      -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   351,
     352,   353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,    -1,   381,
      -1,    -1,   384,    -1,    -1,   387,    -1,   389,    -1,   391,
     392,   393,     4,     5,     6,     7,     8,    -1,    -1,    -1,
      -1,    -1,    -1,   405,    -1,    -1,    -1,    -1,    -1,   411,
      22,    -1,    -1,    25,    26,    27,    -1,    29,    30,    31,
      -1,    -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,
      -1,    43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,
      -1,    -1,    54,    55,    56,    57,    58,    59,    -1,    -1,
      62,    63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,
      72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      -1,    83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,
      92,    -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,
      -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,
      -1,    -1,   114,   115,    -1,   117,   118,   119,   120,    -1,
      -1,    -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,
      -1,   133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,
      -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,
      -1,   153,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,
      -1,   163,   164,   165,   166,   167,   168,   169,    -1,   171,
     172,    -1,   174,   175,   176,   177,   178,   179,   180,   181,
     182,   183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,
      -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,
     202,    -1,    -1,    -1,   206,   207,   208,   209,   210,   211,
     212,   213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,
     222,   223,    -1,    -1,   226,   227,   228,    -1,   230,   231,
     232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,
      -1,    -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,
      -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,
     272,    -1,   274,   275,    -1,    -1,   278,   279,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,
      -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   351,
     352,   353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,    -1,   381,
      -1,    -1,   384,    -1,    -1,   387,    -1,   389,    -1,   391,
     392,   393,     4,     5,     6,     7,     8,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   411,
      22,    -1,    -1,    25,    26,    27,    -1,    29,    30,    31,
      -1,    -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,
      -1,    43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,
      -1,    -1,    54,    55,    56,    57,    58,    59,    -1,    -1,
      62,    63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,
      72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      -1,    83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,
      92,    -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,
      -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,
      -1,    -1,   114,   115,    -1,   117,   118,   119,   120,    -1,
      -1,    -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,
      -1,   133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,
      -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,
      -1,   153,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,
      -1,   163,   164,   165,   166,   167,   168,   169,    -1,   171,
     172,    -1,   174,   175,   176,   177,   178,   179,   180,   181,
     182,   183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,
      -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,
     202,    -1,    -1,    -1,   206,   207,   208,   209,   210,   211,
     212,   213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,
     222,   223,    -1,    -1,   226,   227,   228,    -1,   230,   231,
     232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,
      -1,    -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,
      -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,
     272,    -1,   274,   275,    -1,    -1,   278,   279,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,
      -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   351,
     352,   353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,    -1,   381,
      -1,    -1,   384,    -1,    -1,   387,    -1,   389,    -1,   391,
     392,   393,     4,     5,     6,     7,     8,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   411,
      22,    -1,    -1,    25,    26,    27,    -1,    29,    30,    31,
      -1,    -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,
      -1,    43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,
      -1,    -1,    54,    55,    56,    57,    58,    59,    -1,    -1,
      62,    63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,
      72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      -1,    83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,
      92,    -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,
      -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,
      -1,    -1,   114,   115,    -1,   117,   118,   119,   120,    -1,
      -1,    -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,
      -1,   133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,
      -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,
      -1,   153,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,
      -1,   163,   164,   165,   166,   167,   168,   169,    -1,   171,
     172,    -1,   174,   175,   176,   177,   178,   179,   180,   181,
     182,   183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,
      -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,
     202,    -1,    -1,    -1,   206,   207,   208,   209,   210,   211,
     212,   213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,
     222,   223,    -1,    -1,   226,   227,   228,    -1,   230,   231,
     232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,
      -1,    -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,
      -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,
     272,    -1,   274,   275,    -1,    -1,   278,   279,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,
      -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   351,
     352,   353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,    -1,   381,
      -1,    -1,   384,    -1,    -1,   387,    -1,   389,    -1,   391,
     392,   393,     4,     5,     6,     7,     8,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   411,
      22,    -1,    -1,    25,    26,    27,    -1,    29,    30,    31,
      -1,    -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,
      -1,    43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,
      -1,    -1,    54,    55,    56,    57,    58,    59,    -1,    -1,
      62,    63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,
      72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      -1,    83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,
      92,    -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,
      -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,
      -1,    -1,   114,   115,    -1,   117,   118,   119,   120,    -1,
      -1,    -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,
      -1,   133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,
      -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,
      -1,   153,   154,    -1,    -1,   157,    -1,   159,    -1,    -1,
      -1,   163,   164,   165,   166,   167,   168,   169,    -1,   171,
     172,    -1,   174,   175,   176,   177,   178,   179,   180,   181,
     182,   183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,
      -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,
     202,    -1,    -1,    -1,   206,   207,   208,   209,   210,   211,
     212,   213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,
     222,   223,    -1,    -1,   226,   227,   228,    -1,   230,   231,
     232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,
     242,    -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,
      -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,
     272,    -1,   274,   275,    -1,    -1,   278,   279,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,
      -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   351,
     352,   353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,    -1,   381,
      -1,    -1,   384,    -1,    -1,   387,    -1,   389,    -1,   391,
     392,   393,     4,     5,     6,     7,     8,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   410,    -1,
      22,    -1,    -1,    25,    26,    27,    -1,    29,    30,    31,
      -1,    -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,
      -1,    43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,
      -1,    -1,    54,    55,    56,    57,    58,    59,    -1,    -1,
      62,    63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,
      72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      -1,    83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,
      92,    -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,
      -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,
      -1,    -1,   114,   115,    -1,   117,   118,   119,   120,    -1,
      -1,    -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,
      -1,   133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,
      -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,
      -1,   153,   154,    -1,    -1,   157,    -1,   159,    -1,    -1,
      -1,   163,   164,   165,   166,   167,   168,   169,    -1,   171,
     172,    -1,   174,   175,   176,   177,   178,   179,   180,   181,
     182,   183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,
      -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,
     202,    -1,    -1,    -1,   206,   207,   208,   209,   210,   211,
     212,   213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,
     222,   223,    -1,    -1,   226,   227,   228,    -1,   230,   231,
     232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,
     242,    -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,
      -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,
     272,    -1,   274,   275,    -1,    -1,   278,   279,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,
      -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   351,
     352,   353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,    -1,   381,
      -1,    -1,   384,    -1,    -1,   387,    -1,   389,    -1,   391,
     392,   393,     4,     5,     6,     7,     8,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   410,    -1,
      22,    -1,    -1,    25,    26,    27,    -1,    29,    30,    31,
      -1,    -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,
      -1,    43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,
      -1,    -1,    54,    55,    56,    57,    58,    59,    -1,    -1,
      62,    63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,
      72,    73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,
      -1,    83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,
      92,    -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,
      -1,    -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,
      -1,    -1,   114,   115,    -1,   117,   118,   119,   120,    -1,
      -1,    -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,
      -1,   133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,
      -1,   143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,
      -1,   153,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,
      -1,   163,   164,   165,   166,   167,   168,   169,    -1,   171,
     172,    -1,   174,   175,   176,   177,   178,   179,   180,   181,
     182,   183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,
      -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,
     202,    -1,    -1,    -1,   206,   207,   208,   209,   210,   211,
     212,   213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,
     222,   223,    -1,    -1,   226,   227,   228,    -1,   230,   231,
     232,    -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,
      -1,    -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,
      -1,   253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,
     262,    -1,    -1,    -1,   266,    -1,   268,    -1,    -1,   271,
     272,    -1,   274,   275,    -1,    -1,   278,   279,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,   290,    -1,
     292,    -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   307,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,
      -1,   323,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,
      -1,   343,    -1,    -1,    75,    -1,    -1,    -1,    -1,   351,
     352,   353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    75,    -1,    -1,    -1,    -1,   379,    -1,   381,
      -1,    -1,   384,    -1,    -1,   387,    -1,   389,    75,   391,
     392,   393,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   410,    -1,
      -1,    -1,    -1,    -1,   145,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   155,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   145,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   155,    -1,    -1,    -1,   187,    -1,   145,    -1,
      -1,    -1,    -1,    -1,    -1,   196,   197,    -1,   155,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
      -1,    -1,    -1,    -1,   187,    -1,   217,    -1,    -1,    -1,
      -1,    75,    -1,   196,   197,    -1,    -1,    -1,    -1,    -1,
     187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,
     197,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     217,    -1,    -1,    -1,    -1,    75,   267,    -1,    -1,    -1,
      -1,    -1,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   145,    -1,    -1,   267,    -1,    -1,    -1,    -1,    -1,
      -1,   155,    -1,    -1,    -1,    -1,    -1,    -1,   309,    -1,
     267,    -1,    -1,    -1,    -1,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   187,    -1,   145,   309,    -1,    75,    -1,
      -1,    -1,   196,   197,    -1,   155,    -1,    -1,    -1,    -1,
      -1,    -1,   309,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   187,    -1,    -1,
      -1,    75,    -1,    -1,    -1,    -1,   196,   197,    -1,    -1,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,    -1,   405,   406,    -1,   217,   145,    -1,
      -1,    -1,    -1,   267,    -1,    -1,    -1,    -1,   155,    -1,
      -1,   394,   395,   396,   397,   398,   399,   400,    -1,    -1,
     403,    -1,   405,   406,    -1,    -1,    -1,   394,   395,   396,
     397,   398,   399,   400,    -1,    -1,   403,    -1,   405,   406,
     187,   145,    -1,    -1,    -1,   309,    -1,   267,    -1,   196,
     197,   155,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,   309,
      -1,    -1,   196,   197,    -1,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    75,    -1,
     267,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     394,   395,   396,   397,   398,   399,   400,    -1,    -1,   403,
      -1,   405,   406,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    75,   309,   267,    -1,    -1,    -1,   124,    -1,    -1,
      -1,    -1,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,    -1,   405,   406,    -1,   145,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,    -1,
      -1,    -1,    -1,    -1,    -1,   309,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    75,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
     187,   145,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,
     197,   155,    -1,    -1,    -1,    -1,    -1,   394,   395,   396,
     397,   398,   399,   400,    -1,    -1,   403,    -1,   405,   406,
     217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   196,   197,    75,    -1,    -1,   145,    -1,    -1,
     394,   395,   396,   397,   398,   399,   400,   155,    -1,   403,
      -1,   405,   406,   217,    -1,    -1,    -1,    -1,    -1,    -1,
     267,    -1,    -1,    -1,    -1,    -1,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    -1,    -1,    -1,   187,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,
      -1,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    -1,   309,   267,   145,    -1,    -1,    -1,    -1,   217,
      -1,    -1,    -1,    -1,   155,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    75,    -1,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,   309,   187,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   196,   197,    75,    -1,   267,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,
      -1,    75,    -1,    -1,    -1,    -1,    -1,   394,   395,   396,
     397,   398,   399,   400,    -1,    -1,   403,    -1,    -1,   406,
      75,   309,   145,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   155,    -1,    -1,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,   267,   145,    -1,    -1,
     394,   395,   396,   397,   398,   399,   400,   155,    -1,   403,
      -1,   405,   406,    -1,   187,    -1,    -1,    -1,    -1,    -1,
      -1,   145,    -1,   196,   197,    -1,    -1,    -1,    -1,    -1,
      -1,   155,    -1,    -1,    -1,    -1,    -1,    -1,   309,   187,
     145,    -1,    -1,    -1,   217,    -1,    -1,    -1,   196,   197,
     155,    75,    -1,    -1,    -1,    -1,   394,   395,   396,   397,
     398,   399,   400,   187,    -1,   403,    -1,   405,   406,   217,
      -1,    -1,   196,   197,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   196,   197,   217,   267,    -1,    -1,    -1,    -1,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
      -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,   267,
      -1,   145,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,   155,   403,    -1,   405,   406,   309,    -1,    -1,    -1,
      -1,    -1,    -1,   267,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   309,   267,   187,    -1,    75,    -1,    -1,    -1,    -1,
      -1,    -1,   196,   197,    -1,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,   309,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   309,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   394,   395,   396,   397,   398,   399,   400,    -1,    -1,
     403,    -1,   405,   406,    -1,   145,    -1,    -1,    -1,    -1,
      -1,    75,    -1,   267,    -1,   155,   394,   395,   396,   397,
     398,   399,   400,    -1,    -1,   403,    -1,   405,   406,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
     394,   395,   396,   397,   398,   399,   400,   187,    -1,   403,
      -1,   405,   406,    -1,    -1,   309,   196,   197,    -1,   394,
     395,   396,   397,   398,   399,   400,    -1,    -1,   403,    -1,
     405,   406,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,   145,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   155,    -1,    -1,    -1,    75,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   187,    -1,    -1,    -1,   267,    -1,    -1,
      -1,    -1,   196,   197,    -1,    -1,    -1,    -1,    -1,    -1,
     394,   395,   396,   397,   398,   399,   400,    -1,    -1,   403,
      -1,    -1,   406,   217,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    75,    -1,    -1,   145,    -1,    -1,    -1,   309,
      -1,    -1,    -1,    -1,    -1,   155,    -1,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   267,    -1,    -1,    -1,   187,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    -1,    -1,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      -1,    -1,   145,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,    -1,   155,    75,    -1,   309,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,    -1,    -1,   406,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   196,   197,    -1,    75,   267,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   145,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   155,    -1,    -1,    -1,    -1,    -1,   309,
     394,   395,   396,   397,   398,   399,   400,    -1,    -1,   403,
      -1,    -1,   406,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    -1,   267,   187,   145,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   196,   197,   155,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   309,    -1,   187,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    75,
      -1,    -1,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,    -1,    -1,   406,    -1,   217,    -1,
      -1,    -1,    -1,    75,    -1,   267,    -1,    -1,    -1,    -1,
      -1,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    -1,   309,   267,   145,
      -1,   394,   395,   396,   397,   398,   399,   400,    -1,   155,
     403,    -1,    -1,   406,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   145,    -1,    -1,    -1,    75,    -1,    -1,
      -1,    -1,    -1,   155,    -1,    -1,    -1,    -1,    -1,    -1,
     309,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     196,   197,    75,    -1,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,   187,    -1,    -1,    -1,    -1,
      -1,   217,    -1,    -1,   196,   197,    -1,    -1,    -1,    -1,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    -1,    -1,   406,   217,    -1,   145,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,    -1,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
      75,   267,   145,    -1,    -1,   394,   395,   396,   397,   398,
     399,   400,   155,    -1,   403,    -1,    -1,   406,    -1,   187,
      -1,    -1,    -1,    -1,    -1,   267,    -1,    -1,   196,   197,
      -1,    -1,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,   309,   187,    -1,    -1,    -1,    -1,   217,
      -1,    -1,    -1,   196,   197,    75,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   309,    -1,    -1,
     145,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,
     155,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    75,   267,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   196,   197,    -1,   267,   145,    -1,    -1,   394,   395,
     396,   397,   398,   399,   400,   155,    -1,   403,    -1,    -1,
     406,   309,   217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    -1,    -1,   406,    -1,   309,   187,   145,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,   155,    -1,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      -1,    -1,   267,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,
     197,    -1,    -1,    -1,    -1,    -1,   394,   395,   396,   397,
     398,   399,   400,    -1,   309,   403,    -1,    -1,   406,    -1,
     217,    -1,    -1,    -1,    -1,    -1,    75,   267,    -1,    -1,
      -1,   394,   395,   396,   397,   398,   399,   400,    -1,    -1,
     403,    -1,    -1,   406,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,    -1,    -1,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,   309,
     267,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    -1,    -1,    -1,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,    -1,   145,    -1,    -1,   394,
     395,   396,   397,   398,   399,   400,   155,    -1,   403,    -1,
      75,   406,   309,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    75,    -1,    -1,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    75,   187,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    -1,
      75,    -1,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,    -1,    -1,   406,    -1,   217,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     145,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     155,    -1,    -1,    75,   145,    -1,    -1,   394,   395,   396,
     397,   398,   399,   400,   155,    -1,   403,   145,    -1,   406,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,   267,    -1,
     145,    -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     155,   196,   197,    -1,    -1,    -1,   187,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   196,   197,    -1,    -1,   187,
      -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,   196,   197,
     309,    -1,   187,   145,    -1,    -1,   217,    -1,    -1,    -1,
      -1,   196,   197,   155,    -1,    -1,    -1,    -1,    -1,   217,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   267,    -1,    -1,   187,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   196,   197,   267,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,    -1,   267,
      -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,
      -1,    -1,   267,    -1,   309,   394,   395,   396,   397,   398,
     399,   400,    -1,    -1,   403,    -1,    -1,   406,   309,    -1,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      -1,   309,    -1,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    75,   309,   267,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
      -1,    -1,    -1,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    -1,    -1,    -1,    75,   309,    -1,   394,
     395,   396,   397,   398,   399,   400,    -1,    -1,   403,    75,
      -1,   406,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,   145,    -1,   406,   394,   395,   396,   397,
     398,   399,   400,   155,    75,   403,    -1,    -1,   406,   394,
     395,   396,   397,   398,   399,   400,    -1,    -1,   403,    75,
      -1,   406,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   187,   145,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   196,   197,   155,    -1,    -1,   145,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,   155,
      -1,   403,    -1,    -1,   406,   217,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   145,    -1,    -1,    -1,   187,    -1,
      -1,    -1,    -1,    -1,   155,    -1,    -1,   196,   197,   145,
      -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,
     196,   197,    -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,
      -1,    -1,    -1,    -1,    -1,   267,   187,    -1,    -1,    -1,
      -1,   217,    -1,    -1,    -1,   196,   197,    -1,    -1,    -1,
      -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     196,   197,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   309,   267,    -1,
      -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   267,    -1,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   267,    -1,    -1,    -1,
     309,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   267,    -1,   309,    -1,    -1,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   309,    75,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    -1,   309,   406,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,
      -1,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    -1,    75,    -1,    -1,   394,   395,   396,   397,   398,
     399,   400,    -1,    -1,   403,    -1,    -1,   406,   394,   395,
     396,   397,   398,   399,   400,    -1,    -1,   403,    -1,   145,
     406,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,
      -1,    75,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,    -1,    -1,   406,    -1,    75,   394,   395,
     396,   397,   398,   399,   400,    -1,    -1,   403,    -1,    -1,
     406,   187,   145,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     196,   197,   155,    -1,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   145,    -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,
      -1,   155,    -1,   196,   197,    -1,    -1,   145,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,    -1,    -1,
      -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,
      75,   267,    -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   196,   197,    -1,    -1,    -1,    -1,    -1,   187,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,
      -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   309,   267,    -1,    -1,    -1,    -1,   217,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
     145,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     155,    -1,    -1,   267,    -1,    -1,   309,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,    -1,   267,
      -1,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   196,   197,    -1,    75,   309,    -1,    -1,   394,   395,
     396,   397,   398,   399,   400,    -1,    -1,   403,    -1,    -1,
     406,   309,   217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    75,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,    -1,    -1,    75,    -1,    -1,
      -1,   394,   395,   396,   397,   398,   399,   400,    -1,    -1,
     403,    -1,    -1,   406,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   267,    -1,   145,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   155,    -1,    -1,    -1,    -1,    -1,
     394,   395,   396,   397,   398,   399,   400,    -1,    -1,   403,
      75,    -1,   406,   145,    -1,    -1,   394,   395,   396,   397,
     398,   399,   400,   155,   309,   403,   187,   145,   406,    -1,
      -1,    -1,    -1,    -1,    -1,   196,   197,   155,    -1,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
      -1,    -1,    -1,    -1,    -1,   187,   217,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   196,   197,    -1,    -1,    -1,   187,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,
     145,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,
     155,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   217,
      -1,    -1,    -1,    -1,    -1,    75,   267,    -1,    -1,   394,
     395,   396,   397,   398,   399,   400,    -1,    -1,   403,    -1,
      -1,   406,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   196,   197,    -1,    -1,   267,    -1,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,   309,   267,
      -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    -1,    -1,   145,    -1,   309,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   155,    -1,    -1,    -1,    -1,
      -1,   309,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   267,   335,    75,    -1,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    -1,   187,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    -1,    75,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,    -1,   309,   406,    -1,   217,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    75,   405,   145,    -1,   394,   395,   396,   397,
     398,   399,   400,    -1,   155,   403,    -1,   405,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   267,    -1,   145,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,
      -1,    -1,    -1,    -1,    -1,    -1,   187,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   196,   197,    -1,    -1,   394,
     395,   396,   397,   398,   399,   400,    -1,    -1,   403,   309,
     405,   187,   145,    -1,    -1,    -1,   217,    -1,    -1,    -1,
     196,   197,   155,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   196,   197,    -1,   267,    -1,    -1,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
      -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    75,
      -1,   267,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,    -1,   405,    -1,    -1,   309,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,   309,   267,    75,    -1,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   145,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,
      -1,    -1,    -1,    -1,    -1,    -1,   309,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    75,    -1,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,   187,   403,    75,   405,   145,    -1,    -1,    -1,    -1,
     196,   197,    -1,    -1,    -1,   155,    -1,    -1,   394,   395,
     396,   397,   398,   399,   400,    -1,    -1,   403,    -1,   405,
      -1,   217,    -1,    -1,    -1,    -1,    -1,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,   187,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,   145,    -1,
      -1,   394,   395,   396,   397,   398,   399,   400,   155,    -1,
     403,    -1,   405,   145,    -1,    -1,    -1,   217,    -1,    -1,
      -1,   267,    -1,   155,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,    -1,
     187,    -1,    -1,    75,    -1,    -1,    -1,    -1,    -1,   196,
     197,    -1,    -1,    -1,    -1,   187,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   309,   196,   197,    -1,   267,    -1,    -1,
     217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,
      75,    -1,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   309,
      -1,    -1,    -1,   145,    -1,    -1,    -1,    -1,    -1,    -1,
     267,    -1,    -1,   155,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   267,    -1,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,   394,   395,
     396,   397,   398,   399,   400,   187,    -1,   403,    75,   405,
     145,    -1,   309,    -1,   196,   197,    -1,    -1,    -1,    -1,
     155,    -1,    -1,    -1,    -1,    -1,    -1,   309,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,   187,   403,    75,   405,    -1,    -1,    -1,    -1,
      -1,   196,   197,    -1,    -1,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,    -1,    -1,   145,    -1,
      -1,    -1,   217,    -1,    -1,   267,    -1,    -1,   155,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   394,   395,   396,
     397,   398,   399,   400,    -1,    -1,   403,    -1,   405,    -1,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
     187,   403,    -1,   405,   145,    -1,    -1,   309,    -1,   196,
     197,    75,   267,    -1,   155,    -1,    -1,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
     217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   187,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   309,   196,   197,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,
     267,   145,    -1,    -1,    75,    -1,    -1,    -1,    -1,    -1,
      -1,   155,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    -1,   405,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   309,   187,    -1,    -1,   267,    -1,    -1,    -1,
      -1,    -1,   196,   197,    -1,    -1,    -1,    -1,    -1,   394,
     395,   396,   397,   398,   399,   400,    -1,    -1,   403,    -1,
     405,    -1,    -1,   217,   145,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   155,    -1,    -1,    -1,   309,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
      -1,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    -1,    -1,    -1,    -1,    -1,   187,    -1,    -1,    -1,
      -1,    -1,    -1,   267,    -1,   196,   197,   394,   395,   396,
     397,   398,   399,   400,    -1,    -1,   403,    -1,   405,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    75,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   309,    -1,    75,    -1,    -1,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,    -1,   405,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   267,    -1,    -1,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
      -1,    -1,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,    -1,    -1,   145,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   155,    -1,   145,   309,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,    -1,    -1,
     394,   395,   396,   397,   398,   399,   400,    -1,    -1,   403,
      -1,   405,    -1,    -1,    -1,    75,    -1,   187,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    75,   187,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   217,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,    -1,   405,   145,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   155,    -1,   267,   145,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,   267,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   187,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    -1,   309,
     187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,
     197,   309,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     217,    -1,    -1,    -1,    -1,    -1,    75,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   267,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
     267,    -1,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,    -1,   405,   394,   395,   396,   397,
     398,   399,   400,    75,    -1,   403,   145,   405,    -1,   309,
      -1,    -1,    -1,    -1,    -1,    -1,   155,    -1,    -1,    -1,
      -1,    -1,   309,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    75,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,    -1,    -1,   187,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    -1,
      -1,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    -1,    -1,   145,    -1,    -1,    -1,    -1,   217,    -1,
      -1,    -1,    -1,   155,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,   394,   395,   396,   397,   398,   399,
     400,    75,    -1,   403,   145,   405,    -1,   394,   395,   396,
     397,   398,   399,   400,   155,   187,   403,    -1,   405,    -1,
      -1,    -1,    -1,    -1,   196,   197,    -1,    75,   267,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   217,   187,    -1,    -1,    -1,
      75,    -1,    -1,    -1,    -1,   196,   197,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
     309,   145,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,
      -1,   155,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   267,    -1,   145,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,    -1,    -1,
      -1,    -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,
     145,    -1,   196,   197,    75,    -1,   267,    -1,    -1,    -1,
     155,    -1,    -1,    -1,    -1,    -1,    -1,   309,    -1,   187,
      -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,   196,   197,
      -1,    -1,    -1,    -1,    -1,   394,   395,   396,   397,   398,
     399,   400,   187,    -1,   403,    -1,   405,    -1,   309,   217,
      -1,   196,   197,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   217,   267,   145,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   155,    -1,    -1,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,    -1,   267,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    -1,   405,    -1,   309,   187,    -1,    -1,    -1,
      -1,    -1,   267,    -1,    -1,   196,   197,    -1,    -1,    -1,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,   309,   403,    -1,   405,    -1,   217,    -1,    -1,    -1,
      -1,    -1,    -1,    75,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   309,    -1,    -1,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   267,    -1,    -1,    -1,
     394,   395,   396,   397,   398,   399,   400,    -1,    -1,   403,
      -1,   405,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,   145,    -1,    -1,   394,   395,   396,   397,
     398,   399,   400,   155,    75,   403,    -1,   405,   309,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   394,
     395,   396,   397,   398,   399,   400,    -1,    -1,   403,    -1,
     405,    -1,    -1,    -1,    -1,   187,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   196,   197,    -1,    -1,    75,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   145,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   155,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,    -1,   405,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   267,   187,    -1,   145,    -1,
      -1,    -1,    -1,    -1,    -1,   196,   197,    -1,   155,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   309,    -1,    -1,
     187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,
     197,    -1,    -1,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     217,    -1,    -1,    -1,    -1,    75,   267,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,    -1,    -1,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,   309,    75,
     267,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    -1,   405,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    75,    -1,   145,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   155,    75,    -1,    -1,    -1,
      -1,    -1,   309,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    75,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   187,    -1,   145,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    -1,   155,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,   145,   405,    -1,    -1,   217,    -1,    -1,
      -1,    -1,    -1,   155,    -1,    -1,   145,    -1,    -1,    -1,
      -1,   187,    -1,    -1,    -1,    -1,   155,    -1,    -1,    -1,
     196,   197,    -1,    -1,   145,    -1,    -1,   394,   395,   396,
     397,   398,   399,   400,   155,   187,   403,    -1,   405,    -1,
      -1,   217,    -1,    -1,   196,   197,    -1,   267,   187,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,    -1,
      -1,    -1,    -1,    -1,    -1,   217,   187,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   196,   197,    -1,   217,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   309,
      -1,   267,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,
      -1,    -1,    -1,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    -1,    -1,   267,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,    -1,    -1,   267,    -1,
      -1,    -1,    -1,   309,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,    -1,   267,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,   309,    -1,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    75,
     309,    -1,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    75,   403,    -1,   405,    -1,    -1,   309,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      75,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    75,    -1,    -1,    -1,    -1,   394,   395,
     396,   397,   398,   399,   400,    75,    -1,   403,    -1,   405,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   145,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,   155,
      -1,   403,   145,   405,    -1,   394,   395,   396,   397,   398,
     399,   400,   155,    -1,   403,    -1,   405,    -1,    -1,    -1,
     145,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
     155,   187,   403,   145,   405,    -1,    -1,    -1,    -1,    -1,
     196,   197,    -1,   155,   187,   145,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   196,   197,   155,    -1,    -1,    -1,    -1,
      -1,   217,   187,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   196,   197,    -1,   217,   187,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   196,   197,    -1,   187,    -1,    -1,
      -1,    -1,   217,    -1,    -1,    -1,   196,   197,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,
      -1,   267,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,    -1,    -1,    -1,   267,    -1,    -1,    -1,    -1,    -1,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      -1,    -1,   267,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   309,    -1,   267,     9,    10,    11,    12,
      13,    14,    15,    16,    17,    18,   309,   267,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
      -1,    -1,    -1,    -1,   309,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    75,   309,    -1,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,   309,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    75,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    75,    -1,    -1,    -1,   394,   395,
     396,   397,   398,   399,   400,    -1,    -1,   403,    -1,   405,
      -1,   394,   395,   396,   397,   398,   399,   400,    -1,    -1,
     403,    -1,   405,    -1,    -1,    75,   145,    -1,    -1,   394,
     395,   396,   397,   398,   399,   400,   155,    -1,   403,    -1,
     405,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,   145,   405,   394,   395,   396,   397,   398,   399,
     400,    -1,   155,   403,   145,   405,    -1,    -1,   187,    -1,
      -1,    -1,    -1,    -1,   155,    -1,    -1,   196,   197,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   187,   145,    -1,    -1,   217,    -1,
      -1,    -1,    -1,   196,   197,   155,   187,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   196,   197,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   217,   187,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,   267,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,    -1,    -1,    -1,   267,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   267,    -1,    -1,    -1,
     309,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   309,   267,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    23,    -1,   309,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    33,    -1,    -1,    36,
      -1,    38,    -1,    40,    -1,    42,    -1,    -1,    -1,    -1,
      47,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    55,   309,
      -1,    -1,    -1,    60,    61,    -1,    -1,    -1,    -1,    -1,
      -1,    68,    -1,    -1,    71,   394,   395,   396,   397,   398,
     399,   400,    -1,    -1,   403,    -1,   405,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   394,   395,   396,   397,   398,   399,   400,    -1,    -1,
     403,    -1,   405,   394,   395,   396,   397,   398,   399,   400,
      -1,   118,   403,    -1,   405,    -1,    -1,    -1,    -1,    -1,
      -1,   128,    -1,    -1,    -1,    -1,     4,     5,     6,     7,
       8,    -1,   139,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,    22,   405,    -1,    25,    26,    27,
      -1,    29,    30,    31,    -1,    -1,    -1,    35,    -1,    37,
      -1,    39,    40,    41,    -1,    43,    -1,    -1,    46,    -1,
      48,    -1,    -1,    51,    -1,    -1,    54,    55,    56,    57,
      58,    59,    -1,    -1,    62,    63,    64,    -1,    66,    -1,
      68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,   206,
      78,    79,    80,    81,    -1,    83,    84,    85,    -1,   216,
      88,   218,    -1,    91,    92,    -1,    94,    -1,    -1,    97,
      -1,    -1,    -1,   101,    -1,   232,   104,    -1,    -1,   107,
     108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,   117,
     118,   119,   120,    -1,    -1,    -1,    -1,   125,    -1,   127,
     257,   129,    -1,    -1,    -1,   133,    -1,    -1,   136,   137,
      -1,    -1,   140,    -1,    -1,   143,    -1,    -1,   146,   147,
      -1,    -1,    -1,    -1,    -1,   153,    -1,    -1,    -1,   157,
      -1,   159,    -1,    -1,    -1,   163,   164,   165,   166,   167,
     168,   169,    -1,   171,   172,    -1,   174,   175,   176,   177,
     178,   179,   180,   181,   182,   183,    -1,   185,   186,    -1,
     188,    -1,    -1,   191,    -1,   193,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,   207,
     208,   209,   210,   211,   212,   213,    -1,    -1,    -1,    -1,
     218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,   227,
     228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,   237,
      -1,    -1,   240,    -1,    -1,    -1,    -1,   245,   246,    -1,
      -1,    -1,    -1,    -1,    -1,   253,   254,    -1,    -1,    -1,
     258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,    -1,
     268,    -1,    -1,    -1,   272,    -1,   274,   275,    -1,    -1,
     278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,   297,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   340,   341,    -1,   343,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   351,   352,   353,   354,    -1,   356,    -1,
      -1,    -1,    -1,    -1,    -1,   363,   364,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   379,    -1,   381,    -1,    -1,   384,    -1,    -1,   387,
      -1,   389,    -1,   391,   392,   393,    -1,    -1,    -1,    -1,
     398,     4,     5,     6,     7,     8,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    22,
      -1,    -1,    25,    26,    27,    -1,    29,    30,    31,    -1,
      -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,    -1,
      43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,    -1,
      -1,    54,    55,    56,    57,    58,    59,    -1,    -1,    62,
      63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,    72,
      73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,    -1,
      83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,    92,
      -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,    -1,
      -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,    -1,
      -1,   114,   115,    -1,   117,   118,   119,   120,    -1,    -1,
      -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,    -1,
     133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,    -1,
     143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,    -1,
     153,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,    -1,
     163,   164,   165,   166,   167,   168,   169,    -1,   171,   172,
      -1,   174,   175,   176,   177,   178,   179,   180,   181,   182,
     183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,    -1,
     193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,   202,
      -1,    -1,    -1,   206,   207,   208,   209,   210,   211,   212,
     213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,   222,
     223,    -1,    -1,   226,   227,   228,    -1,   230,   231,   232,
      -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,    -1,
      -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,    -1,
     253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,   262,
      -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,   272,
      -1,   274,   275,    -1,    -1,   278,   279,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,   292,
      -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   307,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,    -1,
     343,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   351,   352,
     353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,    -1,
     363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   379,    -1,   381,    -1,
      -1,   384,    -1,    -1,   387,    -1,   389,    -1,   391,   392,
     393,    -1,    -1,    -1,    -1,   398,     4,     5,     6,     7,
       8,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    22,    -1,    -1,    25,    26,    27,
      -1,    29,    30,    31,    -1,    -1,    -1,    35,    -1,    37,
      -1,    39,    40,    41,    -1,    43,    -1,    -1,    46,    -1,
      48,    -1,    -1,    51,    -1,    -1,    54,    55,    56,    57,
      58,    59,    -1,    -1,    62,    63,    64,    -1,    66,    -1,
      68,    69,    -1,    -1,    72,    73,    -1,    -1,    -1,    -1,
      78,    79,    80,    81,    -1,    83,    84,    85,    -1,    -1,
      88,    -1,    -1,    91,    92,    -1,    94,    -1,    -1,    97,
      -1,    -1,    -1,   101,    -1,    -1,   104,    -1,    -1,   107,
     108,    -1,   110,   111,    -1,    -1,   114,   115,    -1,   117,
     118,   119,   120,    -1,    -1,    -1,    -1,   125,    -1,   127,
      -1,   129,    -1,    -1,    -1,   133,    -1,    -1,   136,   137,
      -1,    -1,   140,    -1,    -1,   143,    -1,    -1,   146,   147,
      -1,    -1,    -1,    -1,    -1,   153,    -1,    -1,    -1,   157,
      -1,   159,    -1,    -1,    -1,   163,   164,   165,   166,   167,
     168,   169,    -1,   171,   172,    -1,   174,   175,   176,   177,
     178,   179,   180,   181,   182,   183,    -1,   185,   186,    -1,
     188,    -1,    -1,   191,    -1,   193,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   201,   202,    -1,    -1,    -1,   206,   207,
     208,   209,   210,   211,   212,   213,    -1,    -1,    -1,    -1,
     218,    -1,   220,    -1,   222,   223,    -1,    -1,   226,   227,
     228,    -1,   230,   231,   232,    -1,    -1,   235,    -1,   237,
      -1,    -1,   240,    -1,    -1,    -1,    -1,   245,   246,    -1,
      -1,    -1,    -1,    -1,    -1,   253,   254,    -1,    -1,    -1,
     258,    -1,    -1,    -1,   262,    -1,    -1,    -1,   266,    -1,
     268,    -1,    -1,    -1,   272,    -1,   274,   275,    -1,    -1,
     278,   279,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   290,    -1,   292,    -1,   294,   295,   296,   297,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   340,   341,    -1,   343,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   351,   352,   353,   354,    -1,   356,    -1,
      -1,    -1,    -1,    -1,    -1,   363,   364,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   379,    -1,   381,    -1,    -1,   384,    -1,    -1,   387,
      -1,   389,    -1,   391,   392,   393,    -1,    -1,    -1,    -1,
     398,     4,     5,     6,     7,     8,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    22,
      -1,    -1,    25,    26,    27,    -1,    29,    30,    31,    -1,
      -1,    -1,    35,    -1,    37,    -1,    39,    40,    41,    -1,
      43,    -1,    -1,    46,    -1,    48,    -1,    -1,    51,    -1,
      -1,    54,    55,    56,    57,    58,    59,    -1,    -1,    62,
      63,    64,    -1,    66,    -1,    68,    69,    -1,    -1,    72,
      73,    -1,    -1,    -1,    -1,    78,    79,    80,    81,    -1,
      83,    84,    85,    -1,    -1,    88,    -1,    -1,    91,    92,
      -1,    94,    -1,    -1,    97,    -1,    -1,    -1,   101,    -1,
      -1,   104,    -1,    -1,   107,   108,    -1,   110,   111,    -1,
      -1,   114,   115,    -1,   117,   118,   119,   120,    -1,    -1,
      -1,    -1,   125,    -1,   127,    -1,   129,    -1,    -1,    -1,
     133,    -1,    -1,   136,   137,    -1,    -1,   140,    -1,    -1,
     143,    -1,    -1,   146,   147,    -1,    -1,    -1,    -1,    -1,
     153,    -1,    -1,    -1,   157,    -1,   159,    -1,    -1,    -1,
     163,   164,   165,   166,   167,   168,   169,    -1,   171,   172,
      -1,   174,   175,   176,   177,   178,   179,   180,   181,   182,
     183,    -1,   185,   186,    -1,   188,    -1,    -1,   191,    -1,
     193,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   201,   202,
      -1,    -1,    -1,   206,   207,   208,   209,   210,   211,   212,
     213,    -1,    -1,    -1,    -1,   218,    -1,   220,    -1,   222,
     223,    -1,    -1,   226,   227,   228,    -1,   230,   231,   232,
      -1,    -1,   235,    -1,   237,    -1,    -1,   240,    -1,    -1,
      -1,    -1,   245,   246,    -1,    -1,    -1,    -1,    -1,    -1,
     253,   254,    -1,    -1,    -1,   258,    -1,    -1,    -1,   262,
      -1,    -1,    -1,   266,    -1,   268,    -1,    -1,    -1,   272,
      -1,   274,   275,    -1,    -1,   278,   279,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,   290,    -1,   292,
      -1,   294,   295,   296,   297,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   307,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,
     323,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    -1,    -1,    -1,    -1,    -1,    -1,   340,   341,    -1,
     343,    -1,    -1,    75,    -1,    -1,    -1,    -1,   351,   352,
     353,   354,    -1,   356,    -1,    -1,    -1,    -1,    -1,    -1,
     363,   364,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    75,    76,    -1,    -1,    -1,   379,    -1,   381,    -1,
      -1,   384,    -1,    -1,   387,    -1,   389,    75,   391,   392,
     393,    -1,    -1,    -1,    -1,   398,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   145,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   155,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   145,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   155,    -1,    -1,    -1,   187,    -1,   145,    -1,    -1,
      -1,    -1,    -1,    -1,   196,   197,    -1,   155,     9,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    -1,    -1,
      -1,    -1,    -1,   187,    -1,   217,    -1,    -1,    -1,    -1,
      75,    -1,   196,   197,    -1,    -1,    -1,    -1,    -1,   187,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,
      -1,    -1,    -1,   217,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   217,
      -1,    -1,    -1,    -1,    75,   267,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     145,    -1,    -1,   267,    -1,    -1,    -1,    -1,    -1,    -1,
     155,    -1,    -1,    -1,    -1,    -1,    -1,   309,    -1,   267,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   320,   321,
     322,   323,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   187,    -1,   145,   309,   338,   339,   340,    75,
      -1,   196,   197,    -1,   155,    -1,    -1,    -1,   350,   351,
      -1,   309,   354,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   363,   217,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   187,    -1,   380,   381,
      -1,    -1,    -1,    -1,    -1,   196,   197,    -1,    -1,    -1,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    -1,    -1,    -1,    -1,   217,    -1,    -1,   145,
      -1,    -1,   267,    -1,    -1,    -1,    -1,    -1,    -1,   155,
     394,   395,   396,   397,   398,   399,   400,   385,    -1,   403,
      -1,    -1,    -1,    -1,    -1,    -1,   394,   395,   396,   397,
     398,   399,   400,    -1,    -1,   403,    -1,    -1,    -1,    -1,
      -1,   187,    -1,    -1,   309,    -1,   267,    -1,    -1,    -1,
     196,   197,     9,    10,    11,    12,    13,    14,    15,    16,
      17,    18,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   217,    -1,    -1,    -1,    -1,    -1,     9,    10,    11,
      12,    13,    14,    15,    16,    17,    18,    -1,   309,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    -1,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    75,    -1,
     385,   267,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   394,
     395,   396,   397,   398,   399,   400,    -1,    -1,   403,    -1,
      -1,    -1,    -1,    75,    -1,     9,    10,    11,    12,    13,
      14,    15,    16,    17,    18,    75,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   309,    -1,    -1,    75,    -1,    -1,    -1,
      -1,    -1,    -1,   394,   395,   396,   397,   398,   399,   400,
      -1,    -1,   403,    -1,    -1,    -1,    -1,    -1,   145,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   155,    -1,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      -1,    75,    -1,   145,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   155,    -1,   145,    -1,    -1,    -1,    -1,
     187,    -1,    -1,    -1,    -1,   155,   145,    -1,    -1,   196,
     197,    -1,    -1,    -1,    -1,    -1,   155,    -1,   394,   395,
     396,   397,   398,   399,   400,   187,    -1,   403,    -1,    -1,
     217,    -1,    -1,    -1,   196,   197,    75,   187,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   196,   197,   187,    -1,
      -1,   145,    -1,    -1,    -1,   217,    -1,   196,   197,    -1,
      -1,   155,    -1,    -1,    -1,    -1,    -1,   217,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   217,    -1,
     267,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   187,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   196,   197,    -1,   267,   145,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   155,   267,    -1,    -1,
      -1,    -1,   309,   217,    -1,    -1,    -1,    -1,   267,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   309,   187,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   196,   197,   309,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     309,    -1,    -1,   267,    -1,    -1,    -1,    -1,   217,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   394,   395,   396,
     397,   398,   399,   400,    -1,   309,   403,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   267,    -1,
      -1,    -1,   394,   395,   396,   397,   398,   399,   400,    -1,
      -1,   403,    -1,    -1,   394,   395,   396,   397,   398,   399,
     400,    -1,    -1,   403,    -1,   394,   395,   396,   397,   398,
     399,   400,    -1,    -1,   403,    -1,    -1,    -1,    -1,    -1,
     309,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     394,   395,   396,   397,   398,   399,   400,    -1,    -1,   403,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    -1,    -1,   394,   395,   396,   397,   398,
     399,   400,    22,    -1,   403,    25,    26,    27,    -1,    29,
      30,    31,    -1,    -1,    -1,    35,    -1,    37,    -1,    39,
      40,    41,    -1,    43,    -1,    -1,    46,    -1,    48,    -1,
      -1,    51,    -1,    -1,    54,    55,    56,    57,    58,    59,
      -1,    -1,    62,    63,    64,    -1,    66,    -1,    68,    69,
      -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,
      80,    81,    -1,    83,    84,    85,    -1,    -1,    88,    -1,
      -1,    91,    92,    -1,    94,    -1,    -1,    97,    -1,    -1,
      -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,
     110,   111,    -1,    -1,   114,   115,    -1,   117,   118,   119,
     120,    -1,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,
      -1,    -1,    -1,   133,   134,    -1,   136,   137,    -1,    -1,
     140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,
      -1,    -1,    -1,   153,    -1,    -1,    -1,   157,    -1,   159,
      -1,    -1,    -1,   163,   164,   165,   166,   167,   168,   169,
      -1,   171,   172,    -1,   174,   175,   176,   177,   178,   179,
     180,   181,   182,   183,    -1,   185,   186,    -1,   188,    -1,
      -1,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,   209,
     210,   211,   212,   213,    -1,    -1,    -1,    -1,   218,    -1,
     220,    -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,
     230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,
     240,    -1,   242,    -1,    -1,   245,   246,    -1,    -1,    -1,
      -1,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,
      -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,
      -1,    -1,   272,    -1,   274,   275,    -1,    -1,   278,   279,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     340,   341,    -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   351,   352,   353,   354,    -1,   356,    -1,    -1,    -1,
      -1,    -1,    -1,   363,   364,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,
      -1,   381,    -1,    -1,   384,    -1,    -1,   387,    -1,   389,
      -1,   391,   392,   393,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,
      30,    31,    -1,    -1,    -1,    35,    -1,    37,    -1,    39,
      40,    41,    -1,    43,    -1,    -1,    46,    -1,    48,    -1,
      -1,    51,    -1,    -1,    54,    55,    56,    57,    58,    59,
      -1,    -1,    62,    63,    64,    -1,    66,    -1,    68,    69,
      -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,
      80,    81,    -1,    83,    84,    85,    -1,    -1,    88,    -1,
      -1,    91,    92,    -1,    94,    -1,    -1,    97,    -1,    -1,
      -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,
     110,   111,    -1,    -1,   114,   115,    -1,   117,   118,   119,
     120,    -1,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,
      -1,    -1,    -1,   133,    -1,    -1,   136,   137,    -1,    -1,
     140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,
      -1,    -1,    -1,   153,   154,    -1,    -1,   157,    -1,   159,
      -1,    -1,    -1,   163,   164,   165,   166,   167,   168,   169,
      -1,   171,   172,    -1,   174,   175,   176,   177,   178,   179,
     180,   181,   182,   183,    -1,   185,   186,    -1,   188,    -1,
      -1,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,   209,
     210,   211,   212,   213,    -1,    -1,    -1,    -1,   218,    -1,
     220,    -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,
     230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,
     240,    -1,   242,    -1,    -1,   245,   246,    -1,    -1,    -1,
      -1,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,
      -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,
      -1,    -1,   272,    -1,   274,   275,    -1,    -1,   278,   279,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     340,   341,    -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   351,   352,   353,   354,    -1,   356,    -1,    -1,    -1,
      -1,    -1,    -1,   363,   364,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,
      -1,   381,    -1,    -1,   384,    -1,    -1,   387,    -1,   389,
      -1,   391,   392,   393,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,
      30,    31,    -1,    -1,    -1,    35,    -1,    37,    -1,    39,
      40,    41,    -1,    43,    -1,    -1,    46,    -1,    48,    -1,
      -1,    51,    -1,    -1,    54,    55,    56,    57,    58,    59,
      -1,    -1,    62,    63,    64,    -1,    66,    -1,    68,    69,
      -1,    -1,    72,    73,    -1,    -1,    76,    -1,    78,    79,
      80,    81,    -1,    83,    84,    85,    -1,    -1,    88,    -1,
      -1,    91,    92,    -1,    94,    -1,    -1,    97,    -1,    -1,
      -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,
     110,   111,    -1,    -1,   114,   115,    -1,   117,   118,   119,
     120,    -1,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,
      -1,    -1,    -1,   133,    -1,    -1,   136,   137,    -1,    -1,
     140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,
      -1,    -1,    -1,   153,    -1,    -1,    -1,   157,    -1,   159,
      -1,    -1,    -1,   163,   164,   165,   166,   167,   168,   169,
      -1,   171,   172,    -1,   174,   175,   176,   177,   178,   179,
     180,   181,   182,   183,    -1,   185,   186,    -1,   188,    -1,
      -1,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,   209,
     210,   211,   212,   213,    -1,    -1,    -1,    -1,   218,    -1,
     220,    -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,
     230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,
     240,    -1,   242,    -1,    -1,   245,   246,    -1,    -1,    -1,
      -1,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,
      -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,
      -1,    -1,   272,    -1,   274,   275,    -1,    -1,   278,   279,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     340,   341,    -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   351,   352,   353,   354,    -1,   356,    -1,    -1,    -1,
      -1,    -1,    -1,   363,   364,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,
      -1,   381,    -1,    -1,   384,    -1,    -1,   387,    -1,   389,
      -1,   391,   392,   393,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,
      30,    31,    -1,    -1,    -1,    35,    -1,    37,    -1,    39,
      40,    41,    -1,    43,    -1,    -1,    46,    -1,    48,    -1,
      -1,    51,    -1,    -1,    54,    55,    56,    57,    58,    59,
      -1,    -1,    62,    63,    64,    -1,    66,    -1,    68,    69,
      -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,
      80,    81,    -1,    83,    84,    85,    -1,    -1,    88,    -1,
      -1,    91,    92,    -1,    94,    -1,    -1,    97,    -1,    -1,
      -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,
     110,   111,    -1,    -1,   114,   115,    -1,   117,   118,   119,
     120,    -1,    -1,    -1,   124,   125,    -1,   127,    -1,   129,
      -1,    -1,    -1,   133,    -1,    -1,   136,   137,    -1,    -1,
     140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,
      -1,    -1,    -1,   153,    -1,    -1,    -1,   157,    -1,   159,
      -1,    -1,    -1,   163,   164,   165,   166,   167,   168,   169,
      -1,   171,   172,    -1,   174,   175,   176,   177,   178,   179,
     180,   181,   182,   183,    -1,   185,   186,    -1,   188,    -1,
      -1,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,   209,
     210,   211,   212,   213,    -1,    -1,    -1,    -1,   218,    -1,
     220,    -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,
     230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,
     240,    -1,    -1,    -1,    -1,   245,   246,    -1,    -1,    -1,
      -1,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,
      -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,
      -1,    -1,   272,    -1,   274,   275,    -1,    -1,   278,   279,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     340,   341,    -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   351,   352,   353,   354,    -1,   356,    -1,    -1,    -1,
      -1,    -1,    -1,   363,   364,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,
      -1,   381,    -1,    -1,   384,    -1,    -1,   387,    -1,   389,
      -1,   391,   392,   393,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,
      30,    31,    -1,    -1,    -1,    35,    -1,    37,    -1,    39,
      40,    41,    -1,    43,    -1,    -1,    46,    -1,    48,    -1,
      -1,    51,    -1,    -1,    54,    55,    56,    57,    58,    59,
      -1,    -1,    62,    63,    64,    -1,    66,    -1,    68,    69,
      -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,
      80,    81,    -1,    83,    84,    85,    -1,    -1,    88,    -1,
      -1,    91,    92,    -1,    94,    -1,    -1,    97,    -1,    -1,
      -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,
     110,   111,    -1,    -1,   114,   115,    -1,   117,   118,   119,
     120,    -1,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,
      -1,    -1,    -1,   133,    -1,    -1,   136,   137,    -1,    -1,
     140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,
      -1,    -1,    -1,   153,    -1,    -1,    -1,   157,    -1,   159,
      -1,    -1,    -1,   163,   164,   165,   166,   167,   168,   169,
      -1,   171,   172,    -1,   174,   175,   176,   177,   178,   179,
     180,   181,   182,   183,    -1,   185,   186,    -1,   188,    -1,
      -1,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,   209,
     210,   211,   212,   213,    -1,    -1,    -1,    -1,   218,    -1,
     220,    -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,
     230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,
     240,    -1,   242,    -1,    -1,   245,   246,    -1,    -1,    -1,
      -1,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,
      -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,
      -1,    -1,   272,    -1,   274,   275,    -1,    -1,   278,   279,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     340,   341,    -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   351,   352,   353,   354,    -1,   356,    -1,    -1,    -1,
      -1,    -1,    -1,   363,   364,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,
      -1,   381,    -1,    -1,   384,    -1,    -1,   387,    -1,   389,
      -1,   391,   392,   393,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,
      30,    31,    -1,    -1,    -1,    35,    -1,    37,    -1,    39,
      40,    41,    -1,    43,    -1,    -1,    46,    -1,    48,    -1,
      -1,    51,    -1,    -1,    54,    55,    56,    57,    58,    59,
      -1,    -1,    62,    63,    64,    -1,    66,    -1,    68,    69,
      -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,
      80,    81,    -1,    83,    84,    85,    -1,    -1,    88,    -1,
      -1,    91,    92,    -1,    94,    -1,    -1,    97,    -1,    -1,
      -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,
     110,   111,    -1,    -1,   114,   115,    -1,   117,   118,   119,
     120,    -1,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,
      -1,    -1,    -1,   133,    -1,    -1,   136,   137,    -1,    -1,
     140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,
      -1,    -1,    -1,   153,    -1,    -1,    -1,   157,    -1,   159,
      -1,    -1,    -1,   163,   164,   165,   166,   167,   168,   169,
      -1,   171,   172,    -1,   174,   175,   176,   177,   178,   179,
     180,   181,   182,   183,    -1,   185,   186,    -1,   188,    -1,
      -1,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   201,   202,    -1,   204,    -1,   206,   207,   208,   209,
     210,   211,   212,   213,    -1,    -1,    -1,    -1,   218,    -1,
     220,    -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,
     230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,
     240,    -1,    -1,    -1,    -1,   245,   246,    -1,    -1,    -1,
      -1,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,
      -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,
      -1,    -1,   272,    -1,   274,   275,    -1,    -1,   278,   279,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     340,   341,    -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   351,   352,   353,   354,    -1,   356,    -1,    -1,    -1,
      -1,    -1,    -1,   363,   364,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,
      -1,   381,    -1,    -1,   384,    -1,    -1,   387,    -1,   389,
      -1,   391,   392,   393,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,
      30,    31,    -1,    -1,    -1,    35,    -1,    37,    -1,    39,
      40,    41,    -1,    43,    -1,    -1,    46,    -1,    48,    -1,
      -1,    51,    -1,    -1,    54,    55,    56,    57,    58,    59,
      -1,    -1,    62,    63,    64,    -1,    66,    -1,    68,    69,
      -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,
      80,    81,    -1,    83,    84,    85,    -1,    -1,    88,    -1,
      -1,    91,    92,    -1,    94,    -1,    -1,    97,    -1,    -1,
      -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,
     110,   111,    -1,    -1,   114,   115,    -1,   117,   118,   119,
     120,    -1,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,
      -1,    -1,    -1,   133,    -1,    -1,   136,   137,    -1,    -1,
     140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,
      -1,    -1,    -1,   153,    -1,    -1,    -1,   157,    -1,   159,
      -1,    -1,    -1,   163,   164,   165,   166,   167,   168,   169,
      -1,   171,   172,    -1,   174,   175,   176,   177,   178,   179,
     180,   181,   182,   183,    -1,   185,   186,    -1,   188,    -1,
      -1,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,   209,
     210,   211,   212,   213,    -1,    -1,    -1,    -1,   218,    -1,
     220,    -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,
     230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,
     240,    -1,    -1,    -1,    -1,   245,   246,    -1,    -1,    -1,
      -1,    -1,    -1,   253,   254,    -1,    -1,    -1,   258,    -1,
      -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,
      -1,    -1,   272,    -1,   274,   275,    -1,    -1,   278,   279,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,   294,   295,   296,   297,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   307,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   323,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     340,   341,    -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   351,   352,   353,   354,    -1,   356,    -1,    -1,    -1,
      -1,    -1,    -1,   363,   364,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,
      -1,   381,    -1,    -1,   384,    -1,    -1,   387,    -1,   389,
      -1,   391,   392,   393,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    22,    -1,    -1,    25,    26,    27,    -1,    29,
      30,    31,    -1,    -1,    -1,    35,    -1,    37,    -1,    39,
      40,    41,    -1,    43,    -1,    -1,    46,    -1,    48,    -1,
      -1,    51,    -1,    -1,    54,    55,    56,    57,    58,    59,
      -1,    -1,    62,    63,    64,    -1,    66,    -1,    68,    69,
      -1,    -1,    72,    73,    -1,    -1,    -1,    -1,    78,    79,
      80,    81,    -1,    83,    84,    85,    -1,    -1,    88,    -1,
      -1,    91,    92,    -1,    94,    -1,    -1,    97,    -1,    -1,
      -1,   101,    -1,    -1,   104,    -1,    -1,   107,   108,    -1,
     110,   111,    -1,    -1,   114,   115,    -1,   117,   118,   119,
     120,    -1,    -1,    -1,    -1,   125,    -1,   127,    -1,   129,
      -1,    -1,    -1,   133,    -1,    -1,   136,   137,    -1,    -1,
     140,    -1,    -1,   143,    -1,    -1,   146,   147,    -1,    -1,
      -1,    -1,    -1,   153,    -1,    -1,    -1,   157,    -1,   159,
      -1,    -1,    -1,   163,   164,   165,   166,   167,   168,   169,
      -1,   171,   172,    -1,   174,   175,   176,   177,   178,   179,
     180,   181,   182,   183,    -1,   185,   186,    -1,   188,    -1,
      -1,   191,    -1,   193,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   201,   202,    -1,    -1,    -1,   206,   207,   208,   209,
     210,   211,   212,   213,    -1,    -1,    -1,    -1,   218,    -1,
     220,    -1,   222,   223,    -1,    -1,   226,   227,   228,    -1,
     230,   231,   232,    -1,    -1,   235,    -1,   237,    -1,    -1,
     240,    -1,    21,    -1,    23,   245,   246,    -1,    -1,    28,
      -1,    30,    -1,   253,   254,    -1,    -1,    -1,   258,    38,
      -1,    -1,   262,    -1,    -1,    -1,   266,    -1,   268,    -1,
      -1,    -1,   272,    -1,   274,   275,    -1,    -1,   278,   279,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,   294,   295,   296,   297,    -1,    78,
      79,    -1,    -1,    -1,    -1,    -1,    -1,   307,    -1,    82,
      83,    84,    91,    92,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   101,   323,    -1,   104,    -1,    -1,    -1,   108,
      -1,    -1,   111,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     340,   341,    -1,   343,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   351,   352,   353,   354,    -1,   356,    -1,    -1,    -1,
     139,    -1,    -1,   363,   364,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   379,
      -1,   381,    -1,    -1,   384,    -1,    -1,   387,   161,   389,
      23,   391,   392,   393,    -1,   174,    -1,    -1,    -1,    -1,
      33,    -1,   181,    36,    -1,    38,    -1,    40,    -1,    42,
     183,    -1,    -1,   186,    47,    -1,    -1,    -1,    -1,   198,
      -1,    -1,    55,   202,    -1,    -1,    -1,    60,    61,    -1,
      -1,    -1,   211,   212,   213,    68,    -1,    -1,    71,    -1,
     219,    74,    -1,    -1,    -1,    -1,    -1,    -1,   227,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   246,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   255,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   118,    -1,    -1,    -1,    -1,
      -1,    -1,   271,    -1,    -1,   128,   269,   270,   271,    -1,
      -1,   274,   275,   276,   277,   278,   139,   280,   281,    -1,
     283,   284,   285,   286,   287,   288,    -1,    -1,   291,    -1,
     293,    -1,   295,   296,   297,   298,   299,   300,    -1,    -1,
     303,   304,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   343,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   206,   353,    -1,    -1,   356,    -1,    -1,
      -1,    -1,    -1,   216,    -1,   218,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   232,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   381,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   257
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned short yystos[] =
{
       0,     3,     5,    23,    24,    26,    28,    31,    33,    36,
      37,    38,    41,    42,    44,    45,    47,    52,    53,    54,
      56,    57,    59,    60,    61,    62,    64,    66,    69,    70,
      71,    80,    93,   105,   106,   128,   219,   223,   225,   229,
     259,   360,   404,   413,   414,   415,   419,   485,   498,   499,
     503,   505,   507,   512,   514,   519,   521,   525,   526,   611,
     613,   619,   622,   646,   650,   661,   663,   673,   675,   677,
     683,   687,   689,   690,   691,   716,   728,   734,   735,   742,
     744,   766,   769,   770,   771,     4,     5,     6,     7,     8,
      22,    25,    26,    27,    29,    30,    31,    35,    37,    39,
      40,    41,    43,    46,    48,    51,    54,    55,    56,    57,
      58,    59,    62,    63,    64,    66,    68,    69,    72,    73,
      78,    79,    80,    81,    83,    84,    85,    88,    91,    92,
      94,    97,   101,   104,   107,   108,   110,   111,   114,   115,
     117,   118,   119,   120,   125,   127,   129,   133,   136,   137,
     140,   143,   146,   147,   153,   157,   159,   163,   164,   165,
     166,   167,   168,   169,   171,   172,   174,   175,   176,   177,
     178,   179,   180,   181,   182,   183,   185,   186,   188,   191,
     193,   201,   202,   206,   207,   208,   209,   210,   211,   212,
     213,   218,   220,   222,   223,   226,   227,   228,   230,   231,
     232,   235,   237,   240,   245,   246,   253,   254,   258,   262,
     266,   268,   272,   274,   275,   278,   279,   290,   292,   294,
     295,   296,   297,   307,   323,   340,   341,   343,   351,   352,
     353,   354,   356,   363,   364,   379,   381,   384,   387,   389,
     391,   392,   393,   411,   711,   712,   715,   138,   494,   238,
     239,   730,   767,    48,    73,   126,   240,   256,   317,   432,
     433,   434,   444,   480,   651,   612,   139,   240,   253,   317,
     618,   678,   620,    25,    32,    42,    49,    50,    65,    67,
      69,    82,    90,    99,   121,   130,   134,   152,   158,   160,
     173,   187,   189,   190,   215,   242,   247,   248,   249,   250,
     271,   273,   275,   296,   297,   301,   308,   310,   311,   312,
     313,   314,   315,   316,   317,   318,   319,   324,   325,   326,
     328,   329,   330,   331,   332,   333,   334,   336,   337,   340,
     342,   344,   345,   346,   347,   348,   349,   351,   354,   355,
     356,   357,   359,   360,   361,   362,   363,   365,   366,   367,
     368,   369,   370,   371,   372,   373,   374,   375,   376,   377,
     381,   382,   383,   396,   401,   404,   407,   408,   410,   411,
     544,   545,   548,   550,   703,   705,   709,   712,   101,   239,
     730,   730,   688,   730,   684,   243,   712,   529,   530,   664,
      64,    66,    62,   245,    62,   239,   662,   730,   647,   730,
     730,   745,   730,   730,   743,   194,   718,   712,   623,    60,
       0,     3,   525,   711,   712,     4,   193,   214,   411,   239,
     513,   379,   768,   243,   342,   435,   239,   433,   253,   139,
     162,   290,   659,   660,   102,   544,   644,   645,   712,   712,
     342,   617,   239,    48,    62,   107,   136,   159,   205,   208,
     222,   235,   238,   679,   680,   730,   103,   135,   162,   625,
     404,   404,   404,   404,   404,   404,   404,   404,   544,   404,
     404,   404,   404,   404,   404,   559,   560,   561,   544,   404,
     404,   404,   404,   404,   404,   703,   703,   703,   404,   404,
     404,   544,   563,   404,   404,   404,   543,   404,   543,   404,
     404,   404,   404,   404,   404,   404,   404,   404,   404,   404,
     404,   404,   404,   404,   404,   404,   404,   544,   404,   404,
     404,   404,   404,   404,   404,   404,   543,   404,   404,   404,
     404,   404,   404,   404,   404,   404,   404,   404,   404,   404,
     404,   404,   404,   404,   404,   404,   404,   404,   404,   404,
     544,   544,   544,   544,   712,   154,   242,   410,   712,   713,
     712,     9,    10,    11,    12,    13,    14,    15,    16,    17,
      18,    75,   145,   155,   187,   196,   197,   217,   267,   309,
     394,   395,   396,   397,   398,   399,   400,   403,   242,   411,
      97,   124,   162,   694,   711,   729,   520,    48,   508,    48,
      62,   208,   685,   686,    59,   527,    74,   109,   135,   236,
     386,   387,   388,   389,   390,   391,   533,   534,   535,    27,
      33,    48,    62,   100,   125,   127,   129,   139,   140,   143,
     149,   157,   159,   185,   193,   231,   235,   238,   239,   479,
     665,   669,   721,    43,    63,   501,   502,   501,   501,   500,
     501,   616,   711,   162,   649,   506,   515,    23,    33,    36,
      38,    40,    42,    47,    55,    60,    61,    68,    71,    74,
     118,   128,   139,   206,   216,   218,   232,   257,   746,   747,
     748,   522,   504,   746,   717,   103,   626,   649,   529,   674,
       9,    76,   583,   584,   736,   712,   711,   615,   616,   416,
     187,   712,   435,   712,   712,   124,   652,   656,   657,   712,
     659,   406,   192,   116,   712,   617,    88,   264,   406,   681,
     494,    74,   553,   585,   109,   553,   585,   544,   553,   553,
     553,   553,   544,   544,   544,   544,   544,   544,   560,   307,
     562,   709,   405,   544,   544,   544,   556,   557,   556,   544,
     553,   553,   378,   556,   544,   405,   544,   405,   544,   544,
     544,   544,   544,   544,   544,   544,   544,   320,   321,   322,
     323,   338,   339,   340,   350,   351,   354,   363,   380,   381,
     582,   544,   544,   544,   703,   544,   544,   544,   582,   405,
     544,   544,   544,   544,   544,   544,   544,   544,   544,   546,
     548,   405,   544,   544,   544,   544,   544,   544,   544,    86,
     151,   244,   544,   549,   556,   549,   549,   549,   549,   549,
     703,   405,   544,   405,   544,   544,   544,   121,   160,   190,
     215,   301,   602,   405,   544,   127,   157,   231,   722,    19,
     411,   544,   544,   544,   544,   544,   544,   544,   187,   189,
     544,   544,   544,   404,   548,   145,   155,   217,   309,   544,
     544,   544,   544,   547,   548,   544,   544,   344,   544,   344,
     544,   544,   544,   544,   544,   712,    48,   157,   693,   124,
     711,   731,   732,   615,   159,   615,    88,   406,   712,   255,
     772,   773,   398,   537,   538,   539,   535,    39,   239,   159,
     235,   136,   235,   155,   668,   335,   235,    48,   238,   668,
     124,   145,   667,   670,   235,   124,    95,   207,   262,   406,
     494,   615,   615,   240,   750,   238,    29,    62,   749,   100,
     751,   205,   194,   752,   192,   406,   523,   524,   711,   615,
     192,   127,   157,   231,   719,   720,   144,   616,   627,   628,
     405,   134,   242,   676,   704,   712,   712,     7,   119,   712,
     737,   738,   486,   117,   178,   272,   279,   290,   406,   516,
     517,   518,   163,   164,   165,   166,   167,   168,   169,   171,
     172,   417,   418,   116,   711,   422,   192,   656,   711,   712,
     406,   654,   411,   658,   645,   711,   615,   214,   680,   615,
     682,   627,   405,   554,   551,   405,   398,   406,   405,   405,
     405,   405,   406,    76,   406,   406,   406,   405,   406,   405,
     404,   406,   405,   406,   406,   405,   544,   558,   405,   405,
     406,   405,   405,   565,   566,   405,   406,   405,   406,   406,
     406,   405,   406,   405,   406,   406,   406,   405,   406,   406,
     124,   406,   406,   405,   406,   406,   405,   406,   406,   397,
     405,   406,   406,   406,   406,   405,   405,   405,   405,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    75,
     145,   155,   187,   196,   197,   217,   267,   309,   394,   395,
     396,   397,   398,   399,   400,   403,   405,   406,   406,   405,
     406,   405,   124,   406,   406,   544,   568,   568,   568,   124,
     405,   405,   405,   405,   405,   405,   405,   406,   405,   405,
     406,   405,   405,   406,   406,   409,   411,   411,   411,   713,
     544,   712,   189,   556,   115,   589,   404,   548,   544,   547,
       9,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      75,   145,   155,   187,   196,   197,   217,   267,   309,   394,
     395,   396,   397,   398,   399,   400,   403,   544,   544,   411,
     141,    48,   584,   406,   516,   243,   117,   258,   290,   509,
     510,   511,   686,    74,   778,   124,   144,   282,   406,   531,
     532,   598,   609,   541,   544,   707,   712,   145,   671,   711,
     704,   713,   714,   335,   667,   668,   712,   667,   711,   670,
     668,   502,   404,   408,   569,   574,   575,   243,   516,   238,
     404,   759,   759,   759,   759,   398,   711,   712,   756,   748,
     406,   243,   124,   756,   406,   245,   271,   356,   410,   712,
     723,   724,   628,   624,   528,     6,     7,     8,     9,    11,
      12,    13,    14,   119,   739,   741,   263,   586,    21,    23,
      28,    30,    38,    78,    79,    91,    92,   101,   104,   108,
     111,   139,   174,   181,   198,   202,   211,   212,   213,   219,
     227,   246,   255,   271,   343,   353,   356,   437,   438,   487,
     488,   489,   594,   616,   517,     9,     9,     9,     9,     9,
       9,     9,     9,     9,   406,   420,   251,   711,   655,   653,
     411,   657,   124,   398,   712,   614,    89,   224,   495,    47,
     621,   544,   556,   405,   544,   544,    82,   271,   274,   275,
     292,   297,   302,   555,   555,   556,   556,   544,   544,   709,
     544,   544,   406,   544,   327,   564,   544,   567,   556,   344,
     344,   242,   544,   544,   556,   242,   544,   544,   544,   556,
     190,   544,   190,   544,   556,   544,   544,   544,   556,   544,
     544,   544,   544,   544,   544,   544,   544,   187,   189,   544,
     544,   544,   544,   548,   155,   217,   309,   544,   544,   544,
     544,   547,   544,   544,   344,   544,   344,   544,   544,   544,
     544,   544,   544,   544,   544,   544,   544,   544,   124,   124,
     124,   544,   190,   544,   544,   544,   405,   242,   556,   589,
      75,   544,   544,   544,   544,   544,   544,   544,   187,   189,
     544,   544,   544,   404,   548,   145,   155,   217,   309,   544,
     544,   544,   544,   547,   544,   544,   344,   544,   344,   544,
     544,   544,   544,   544,   582,   582,   712,   242,   162,   214,
     265,   733,   732,   242,   510,   774,   569,   200,   201,   599,
     538,    47,   335,   536,   609,   532,   540,   411,   242,   124,
     672,   410,    62,   668,   668,   667,   711,   569,   712,    34,
     142,   148,   184,   229,   236,   346,   361,   406,   573,   711,
     242,   712,   760,   761,   411,   411,   243,   524,   711,   242,
     124,   720,   146,   229,     9,    19,   335,   639,   410,   713,
     639,    60,   229,   261,   404,   429,   629,   633,   773,   775,
     776,   777,   740,   544,   598,    96,    98,   126,   139,   150,
     449,   451,   477,   478,   493,   493,   493,     9,   123,   204,
     478,   493,     9,     9,   639,   640,     9,   114,     9,   149,
     149,   114,     9,     9,    87,     9,     9,     9,     9,     9,
      76,   243,   497,     9,     9,     9,   229,     9,   493,     9,
     437,   406,   404,   411,   448,   452,   710,   712,   242,   242,
     242,   121,   160,   190,   215,   301,   603,   242,   602,   602,
     242,   602,   418,   404,   423,   436,   437,   281,   291,   294,
     445,   421,   260,   586,   712,   569,   411,   658,   629,   552,
     406,   405,   281,   281,   405,   405,   405,   405,   405,   145,
     405,   405,   406,   544,   405,   544,   384,   385,   378,   405,
     544,   544,   405,   405,   405,   405,   405,   405,   406,   405,
     405,   405,   405,   406,   406,   405,   405,   405,   406,   405,
     405,   406,   189,   405,   589,   548,   544,   547,    75,   544,
     544,   406,   405,   405,   335,   405,   405,   406,   406,   544,
     544,   544,   405,   406,   405,   405,   405,   405,   544,   189,
     556,   589,   404,   548,   544,   547,    75,   544,   544,   692,
     265,   157,   526,   586,   242,   242,   600,   602,   145,    71,
      76,   242,   542,   712,   398,   712,   603,   666,   713,   264,
     667,   405,   574,   148,   148,   148,   346,   361,   648,   709,
     569,   199,   576,   576,   569,   569,   584,   405,   406,   398,
     398,   714,   757,   758,   757,   723,   153,   640,   714,   242,
     356,   726,   722,   639,    74,   102,   192,   544,   727,   430,
     630,   404,   636,   641,   405,   429,   632,   706,   707,   709,
     634,   593,   594,   404,   483,   710,   478,    93,   123,   204,
     256,   450,   483,   710,   710,   242,   150,   150,   710,   710,
     603,   602,   712,   602,     9,   602,     9,   603,   603,   595,
     102,   602,   209,   210,   441,   602,   602,   602,   711,   102,
     110,   120,   268,   440,    81,   133,   143,   147,   179,   180,
     182,   439,   404,   640,     6,   119,   188,   442,   710,   242,
     489,   446,   447,   448,   449,   712,    22,   119,   496,   216,
     450,   472,   453,   411,   424,   429,   446,   138,   360,   426,
     695,   252,   404,   569,   593,   586,   405,   544,    85,   544,
     544,   544,   582,   582,   544,   190,   544,   544,   544,   589,
      75,   544,   582,   582,   544,   544,   544,   544,   405,   405,
     405,   190,   405,   556,   589,    75,   544,   582,   582,   695,
     131,   590,   610,   191,   406,   364,   242,   712,   411,   598,
     165,   668,   346,   569,   576,   576,   406,   586,   639,   148,
     148,   192,   260,   122,   138,   259,   577,   761,   341,   221,
     406,   762,   214,   220,   230,   725,   727,   639,   404,   724,
     544,   533,   637,   638,   709,   642,   406,   404,   633,   405,
     405,   406,   772,   598,   644,   544,   150,   150,   478,   404,
      38,   229,   490,   483,   495,   242,   242,   544,   596,   708,
     615,   712,   491,   405,   406,   712,   711,    82,    83,    84,
     161,   183,   186,   229,   269,   270,   271,   274,   275,   276,
     277,   278,   280,   281,   283,   284,   285,   286,   287,   288,
     291,   293,   295,   296,   297,   298,   299,   300,   303,   304,
     381,   454,   457,   458,   459,   460,   712,   405,   405,    76,
     431,   242,   481,   482,   712,   586,   282,   601,   406,   352,
     405,   385,   405,   405,   405,   406,   406,   405,   405,   405,
     544,   405,   405,   405,   405,   406,   405,   544,   144,    87,
     132,   587,    95,   696,   602,   602,   352,   398,     9,   199,
     148,   148,   709,   593,   544,   569,   569,   544,   570,   478,
     578,   578,   578,    87,    51,   233,   237,   266,   392,   393,
     754,   755,   758,   264,   763,    94,   254,   214,   726,   242,
     639,   537,   406,   639,   643,   644,   641,   635,   633,   706,
     405,   483,   481,   102,   102,   452,   406,    77,   105,   597,
     405,   454,   447,   173,   192,   404,   473,   474,   475,   404,
     404,   466,   303,   457,   458,   271,   304,   304,   456,   404,
     461,   462,   289,   455,   461,   461,   404,   404,   466,    30,
      78,   102,   187,   189,   204,   256,   468,   469,   470,    82,
     271,   305,   404,   471,   404,   466,   404,   462,   467,   425,
     436,   404,   429,   405,   406,   597,   404,   603,   544,   405,
     544,   544,   553,   556,   239,   591,   708,   588,   593,   112,
     113,   195,   241,   697,   698,   156,   699,   242,   148,   569,
     569,   639,   601,   192,   571,   192,   572,   404,   579,   242,
     356,   242,   242,   242,    75,   753,   128,   175,   176,   177,
     764,   765,   405,   727,   443,   532,   638,   645,   405,   775,
     404,   405,   275,   296,   297,   705,   496,   708,   468,   125,
     203,    36,    71,   481,   475,   190,   190,   404,   190,   292,
     302,   306,   463,   464,   465,   404,   463,   463,   190,   190,
     463,   703,   705,   189,   150,   150,   470,   229,   190,   190,
     463,   190,   463,   775,   426,   429,   427,   482,   190,   405,
     405,   406,   405,   405,   711,   264,   406,   592,   597,   544,
     598,    87,    87,   112,    87,   698,   234,   241,   700,   701,
      75,   574,   544,   544,   260,   544,   260,   581,   712,   404,
     242,   754,   194,   602,   602,   602,   765,   536,   481,   597,
     492,    89,   188,   224,   229,   476,   476,   405,   405,   405,
     484,   704,   405,   406,   465,   484,   405,   405,   640,   405,
     405,   405,   772,   597,   405,   544,   696,    35,    58,   708,
     358,   604,   704,   704,    87,   704,    87,    87,   701,   166,
     192,   404,   404,   405,   406,   204,   580,   712,   405,   496,
      72,   102,   189,   473,   405,   406,   190,   405,   712,   471,
     471,   428,   405,   699,   597,   712,   704,   704,   704,     9,
     544,   581,   581,   712,   405,   406,   472,   704,   405,   775,
     138,   702,   605,   603,   409,   405,   405,   712,   190,   404,
     631,   404,    75,   156,   405,   632,   539,   606,   607,   608,
     170,   405,   544,   405,   406,     9,   608,   602
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrlab1

/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");			\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)           \
  Current.first_line   = Rhs[1].first_line;      \
  Current.first_column = Rhs[1].first_column;    \
  Current.last_line    = Rhs[N].last_line;       \
  Current.last_column  = Rhs[N].last_column;
#endif

/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX	yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX	yylex (&yylval)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)
# define YYDSYMPRINT(Args)			\
do {						\
  if (yydebug)					\
    yysymprint Args;				\
} while (0)
/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YYDSYMPRINT(Args)
#endif /* !YYDEBUG */

/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*-----------------------------.
| Print this symbol on YYOUT.  |
`-----------------------------*/

static void
#if defined (__STDC__) || defined (__cplusplus)
yysymprint (FILE* yyout, int yytype, YYSTYPE yyvalue)
#else
yysymprint (yyout, yytype, yyvalue)
    FILE* yyout;
    int yytype;
    YYSTYPE yyvalue;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvalue;

  if (yytype < YYNTOKENS)
    {
      YYFPRINTF (yyout, "token %s (", yytname[yytype]);
# ifdef YYPRINT
      YYPRINT (yyout, yytoknum[yytype], yyvalue);
# endif
    }
  else
    YYFPRINTF (yyout, "nterm %s (", yytname[yytype]);

  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyout, ")");
}
#endif /* YYDEBUG. */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
#if defined (__STDC__) || defined (__cplusplus)
yydestruct (int yytype, YYSTYPE yyvalue)
#else
yydestruct (yytype, yyvalue)
    int yytype;
    YYSTYPE yyvalue;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvalue;

  switch (yytype)
    {
      default:
        break;
    }
}



/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
#  define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL
# else
#  define YYPARSE_PARAM_ARG YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
# endif
#else /* !YYPARSE_PARAM */
# define YYPARSE_PARAM_ARG
# define YYPARSE_PARAM_DECL
#endif /* !YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
# ifdef YYPARSE_PARAM
int yyparse (void *);
# else
int yyparse (void);
# endif
#endif




int
yyparse (YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  /* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of parse errors so far.  */
int yynerrs;

  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yychar1 = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with.  */

  if (yychar <= 0)		/* This means end of input.  */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more.  */

      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yychar1 = YYTRANSLATE (yychar);

      /* We have to keep this `#if YYDEBUG', since we use variables
	 which are defined only if `YYDEBUG' is set.  */
      YYDPRINTF ((stderr, "Next token is "));
      YYDSYMPRINT ((stderr, yychar1, yylval));
      YYDPRINTF ((stderr, "\n"));
    }

  /* If the proper action on seeing token YYCHAR1 is to reduce or to
     detect an error, take that action.  */
  yyn += yychar1;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yychar1)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %d (%s), ",
	      yychar, yytname[yychar1]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];



#if YYDEBUG
  /* We have to keep this `#if YYDEBUG', since we use variables which
     are defined only if `YYDEBUG' is set.  */
  if (yydebug)
    {
      int yyi;

      YYFPRINTF (stderr, "Reducing via rule %d (line %d), ",
		 yyn - 1, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (yyi = yyprhs[yyn]; yyrhs[yyi] >= 0; yyi++)
	YYFPRINTF (stderr, "%s ", yytname[yyrhs[yyi]]);
      YYFPRINTF (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif
  switch (yyn)
    {
        case 2:
#line 611 "sql_yacc.yy"
    {
	   THD *thd=current_thd;
	   if (!thd->bootstrap &&
	      (!(thd->lex.select_lex.options & OPTION_FOUND_COMMENT)))
	   {
	     send_error(&current_thd->net,ER_EMPTY_QUERY);
	     YYABORT;
 	   }
	   else
	   {
	     thd->lex.sql_command = SQLCOM_EMPTY_QUERY;
	   }
	}
    break;

  case 3:
#line 624 "sql_yacc.yy"
    {}
    break;

  case 42:
#line 670 "sql_yacc.yy"
    {
	  LEX *lex = Lex;
	  lex->sql_command = SQLCOM_CHANGE_MASTER;
	  bzero((char*) &lex->mi, sizeof(lex->mi));
        }
    break;

  case 43:
#line 676 "sql_yacc.yy"
    {}
    break;

  case 46:
#line 685 "sql_yacc.yy"
    {
	 Lex->mi.host = yyvsp[0].lex_str.str;
       }
    break;

  case 47:
#line 690 "sql_yacc.yy"
    {
	 Lex->mi.user = yyvsp[0].lex_str.str;
       }
    break;

  case 48:
#line 695 "sql_yacc.yy"
    {
	 Lex->mi.password = yyvsp[0].lex_str.str;
       }
    break;

  case 49:
#line 700 "sql_yacc.yy"
    {
	 Lex->mi.log_file_name = yyvsp[0].lex_str.str;
       }
    break;

  case 50:
#line 705 "sql_yacc.yy"
    {
	 Lex->mi.port = yyvsp[0].ulong_num;
       }
    break;

  case 51:
#line 710 "sql_yacc.yy"
    {
	 Lex->mi.pos = yyvsp[0].ulonglong_number;
         /* 
            If the user specified a value < BIN_LOG_HEADER_SIZE, adjust it
            instead of causing subsequent errors. 
            We need to do it in this file, because only there we know that 
            MASTER_LOG_POS has been explicitely specified. On the contrary
            in change_master() (sql_repl.cc) we cannot distinguish between 0
            (MASTER_LOG_POS explicitely specified as 0) and 0 (unspecified),
            whereas we want to distinguish (specified 0 means "read the binlog
            from 0" (4 in fact), unspecified means "don't change the position
            (keep the preceding value)").
         */
         Lex->mi.pos = max(BIN_LOG_HEADER_SIZE, Lex->mi.pos);
       }
    break;

  case 52:
#line 727 "sql_yacc.yy"
    {
	 Lex->mi.connect_retry = yyvsp[0].ulong_num;
       }
    break;

  case 53:
#line 732 "sql_yacc.yy"
    {
	 Lex->mi.relay_log_name = yyvsp[0].lex_str.str;
       }
    break;

  case 54:
#line 737 "sql_yacc.yy"
    {
	 Lex->mi.relay_log_pos = yyvsp[0].ulong_num;
         /* Adjust if < BIN_LOG_HEADER_SIZE (same comment as Lex->mi.pos) */
         Lex->mi.relay_log_pos = max(BIN_LOG_HEADER_SIZE, Lex->mi.relay_log_pos);
       }
    break;

  case 55:
#line 748 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command= SQLCOM_CREATE_TABLE;
	  if (!add_table_to_list(yyvsp[0].table,
				 (yyvsp[-3].num & HA_LEX_CREATE_TMP_TABLE ?
				   &tmp_table_alias : (LEX_STRING*) 0),
				 TL_OPTION_UPDATING))
	    YYABORT;
	  lex->create_list.empty();
	  lex->key_list.empty();
	  lex->col_list.empty();
	  lex->change=NullS;
	  bzero((char*) &lex->create_info,sizeof(lex->create_info));
	  lex->create_info.options=yyvsp[-3].num | yyvsp[-1].num;
	  lex->create_info.db_type= (enum db_type) lex->thd->variables.table_type;
	}
    break;

  case 56:
#line 765 "sql_yacc.yy"
    {Lex->select= &Lex->select_lex;}
    break;

  case 57:
#line 767 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command= SQLCOM_CREATE_INDEX;
	    if (!add_table_to_list(yyvsp[0].table, NULL, TL_OPTION_UPDATING))
	      YYABORT;
	    lex->create_list.empty();
	    lex->key_list.empty();
	    lex->col_list.empty();
	    lex->change=NullS;
	  }
    break;

  case 58:
#line 778 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->key_list.push_back(new Key(yyvsp[-8].key_type,yyvsp[-6].lex_str.str,lex->col_list));
	    lex->col_list.empty();
	  }
    break;

  case 59:
#line 784 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command=SQLCOM_CREATE_DB;
	    lex->name=yyvsp[0].lex_str.str;
            lex->create_info.options=yyvsp[-1].num;
	  }
    break;

  case 60:
#line 791 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command = SQLCOM_CREATE_FUNCTION;
	    lex->udf.name=yyvsp[0].lex_str.str;
	    lex->udf.name_length=yyvsp[0].lex_str.length;
	    lex->udf.type= yyvsp[-2].udf_type;
	  }
    break;

  case 61:
#line 799 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->udf.returns=(Item_result) yyvsp[-2].num;
	    lex->udf.dl=yyvsp[0].lex_str.str;
	  }
    break;

  case 62:
#line 806 "sql_yacc.yy"
    {}
    break;

  case 63:
#line 807 "sql_yacc.yy"
    {}
    break;

  case 64:
#line 810 "sql_yacc.yy"
    {}
    break;

  case 65:
#line 811 "sql_yacc.yy"
    { Select->braces= 1;}
    break;

  case 66:
#line 811 "sql_yacc.yy"
    {}
    break;

  case 67:
#line 815 "sql_yacc.yy"
    {}
    break;

  case 68:
#line 817 "sql_yacc.yy"
    { Select->braces= 0;}
    break;

  case 69:
#line 817 "sql_yacc.yy"
    {}
    break;

  case 70:
#line 819 "sql_yacc.yy"
    { Select->braces= 1;}
    break;

  case 71:
#line 819 "sql_yacc.yy"
    {}
    break;

  case 72:
#line 824 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->lock_option= (using_update_log) ? TL_READ_NO_INSERT : TL_READ;
	    if (lex->sql_command == SQLCOM_INSERT)
	      lex->sql_command= SQLCOM_INSERT_SELECT;
	    else if (lex->sql_command == SQLCOM_REPLACE)
	      lex->sql_command= SQLCOM_REPLACE_SELECT;
	    lex->select->table_list.save_and_clear(&lex->save_list);
	    mysql_init_select(lex);
          }
    break;

  case 73:
#line 835 "sql_yacc.yy"
    { Lex->select->table_list.push_front(&Lex->save_list); }
    break;

  case 74:
#line 839 "sql_yacc.yy"
    {}
    break;

  case 75:
#line 840 "sql_yacc.yy"
    {}
    break;

  case 76:
#line 843 "sql_yacc.yy"
    { yyval.num= 0; }
    break;

  case 77:
#line 844 "sql_yacc.yy"
    { yyval.num= yyvsp[0].num;}
    break;

  case 78:
#line 847 "sql_yacc.yy"
    { yyval.num=yyvsp[0].num; }
    break;

  case 79:
#line 848 "sql_yacc.yy"
    { yyval.num= yyvsp[-1].num | yyvsp[0].num; }
    break;

  case 80:
#line 851 "sql_yacc.yy"
    { yyval.num=HA_LEX_CREATE_TMP_TABLE; }
    break;

  case 81:
#line 854 "sql_yacc.yy"
    { yyval.num= 0; }
    break;

  case 82:
#line 855 "sql_yacc.yy"
    { yyval.num=HA_LEX_CREATE_IF_NOT_EXISTS; }
    break;

  case 87:
#line 866 "sql_yacc.yy"
    { Lex->create_info.db_type= yyvsp[0].db_type; }
    break;

  case 88:
#line 867 "sql_yacc.yy"
    { Lex->create_info.max_rows= yyvsp[0].ulonglong_number; Lex->create_info.used_fields|= HA_CREATE_USED_MAX_ROWS;}
    break;

  case 89:
#line 868 "sql_yacc.yy"
    { Lex->create_info.min_rows= yyvsp[0].ulonglong_number; Lex->create_info.used_fields|= HA_CREATE_USED_MIN_ROWS;}
    break;

  case 90:
#line 869 "sql_yacc.yy"
    { Lex->create_info.avg_row_length=yyvsp[0].ulong_num; Lex->create_info.used_fields|= HA_CREATE_USED_AVG_ROW_LENGTH;}
    break;

  case 91:
#line 870 "sql_yacc.yy"
    { Lex->create_info.password=yyvsp[0].lex_str.str; }
    break;

  case 92:
#line 871 "sql_yacc.yy"
    { Lex->create_info.comment=yyvsp[0].lex_str.str; }
    break;

  case 93:
#line 872 "sql_yacc.yy"
    { Lex->create_info.auto_increment_value=yyvsp[0].ulonglong_number; Lex->create_info.used_fields|= HA_CREATE_USED_AUTO;}
    break;

  case 94:
#line 873 "sql_yacc.yy"
    { Lex->create_info.table_options|= yyvsp[0].ulong_num ? HA_OPTION_PACK_KEYS : HA_OPTION_NO_PACK_KEYS; Lex->create_info.used_fields|= HA_CREATE_USED_PACK_KEYS;}
    break;

  case 95:
#line 874 "sql_yacc.yy"
    { Lex->create_info.table_options&= ~(HA_OPTION_PACK_KEYS | HA_OPTION_NO_PACK_KEYS); Lex->create_info.used_fields|= HA_CREATE_USED_PACK_KEYS;}
    break;

  case 96:
#line 875 "sql_yacc.yy"
    { Lex->create_info.table_options|= yyvsp[0].ulong_num ? HA_OPTION_CHECKSUM : HA_OPTION_NO_CHECKSUM; }
    break;

  case 97:
#line 876 "sql_yacc.yy"
    { Lex->create_info.table_options|= yyvsp[0].ulong_num ? HA_OPTION_DELAY_KEY_WRITE : HA_OPTION_NO_DELAY_KEY_WRITE; }
    break;

  case 98:
#line 877 "sql_yacc.yy"
    { Lex->create_info.row_type= yyvsp[0].row_type; }
    break;

  case 99:
#line 878 "sql_yacc.yy"
    { Lex->create_info.raid_type= yyvsp[0].ulong_num; Lex->create_info.used_fields|= HA_CREATE_USED_RAID;}
    break;

  case 100:
#line 879 "sql_yacc.yy"
    { Lex->create_info.raid_chunks= yyvsp[0].ulong_num; Lex->create_info.used_fields|= HA_CREATE_USED_RAID;}
    break;

  case 101:
#line 880 "sql_yacc.yy"
    { Lex->create_info.raid_chunksize= yyvsp[0].ulong_num*RAID_BLOCK_SIZE; Lex->create_info.used_fields|= HA_CREATE_USED_RAID;}
    break;

  case 102:
#line 882 "sql_yacc.yy"
    {
	    /* Move the union list to the merge_list */
	    LEX *lex=Lex;
	    TABLE_LIST *table_list= (TABLE_LIST*) lex->select->table_list.first;
	    lex->create_info.merge_list= lex->select->table_list;
	    lex->create_info.merge_list.elements--;
	    lex->create_info.merge_list.first= (byte*) (table_list->next);
	    lex->select->table_list.elements=1;
	    lex->select->table_list.next= (byte**) &(table_list->next);
	    table_list->next=0;
	    lex->create_info.used_fields|= HA_CREATE_USED_UNION;
	  }
    break;

  case 103:
#line 894 "sql_yacc.yy"
    {}
    break;

  case 104:
#line 895 "sql_yacc.yy"
    {}
    break;

  case 105:
#line 896 "sql_yacc.yy"
    { Lex->create_info.merge_insert_method= yyvsp[0].ulong_num; Lex->create_info.used_fields|= HA_CREATE_USED_INSERT_METHOD;}
    break;

  case 106:
#line 897 "sql_yacc.yy"
    { Lex->create_info.data_file_name= yyvsp[0].lex_str.str; }
    break;

  case 107:
#line 898 "sql_yacc.yy"
    { Lex->create_info.index_file_name= yyvsp[0].lex_str.str; }
    break;

  case 108:
#line 901 "sql_yacc.yy"
    { yyval.db_type= DB_TYPE_ISAM; }
    break;

  case 109:
#line 902 "sql_yacc.yy"
    { yyval.db_type= DB_TYPE_MYISAM; }
    break;

  case 110:
#line 903 "sql_yacc.yy"
    { yyval.db_type= DB_TYPE_MRG_MYISAM; }
    break;

  case 111:
#line 904 "sql_yacc.yy"
    { yyval.db_type= DB_TYPE_HEAP; }
    break;

  case 112:
#line 905 "sql_yacc.yy"
    { yyval.db_type= DB_TYPE_HEAP; }
    break;

  case 113:
#line 906 "sql_yacc.yy"
    { yyval.db_type= DB_TYPE_BERKELEY_DB; }
    break;

  case 114:
#line 907 "sql_yacc.yy"
    { yyval.db_type= DB_TYPE_INNODB; }
    break;

  case 115:
#line 910 "sql_yacc.yy"
    { yyval.row_type= ROW_TYPE_DEFAULT; }
    break;

  case 116:
#line 911 "sql_yacc.yy"
    { yyval.row_type= ROW_TYPE_FIXED; }
    break;

  case 117:
#line 912 "sql_yacc.yy"
    { yyval.row_type= ROW_TYPE_DYNAMIC; }
    break;

  case 118:
#line 913 "sql_yacc.yy"
    { yyval.row_type= ROW_TYPE_COMPRESSED; }
    break;

  case 119:
#line 916 "sql_yacc.yy"
    { yyval.ulong_num= RAID_TYPE_0; }
    break;

  case 120:
#line 917 "sql_yacc.yy"
    { yyval.ulong_num= RAID_TYPE_0; }
    break;

  case 121:
#line 918 "sql_yacc.yy"
    { yyval.ulong_num=yyvsp[0].ulong_num;}
    break;

  case 122:
#line 921 "sql_yacc.yy"
    { yyval.ulong_num= MERGE_INSERT_DISABLED; }
    break;

  case 123:
#line 922 "sql_yacc.yy"
    { yyval.ulong_num= MERGE_INSERT_TO_FIRST; }
    break;

  case 124:
#line 923 "sql_yacc.yy"
    { yyval.ulong_num= MERGE_INSERT_TO_LAST; }
    break;

  case 127:
#line 930 "sql_yacc.yy"
    { yyval.udf_type = UDFTYPE_FUNCTION; }
    break;

  case 128:
#line 931 "sql_yacc.yy"
    { yyval.udf_type = UDFTYPE_AGGREGATE; }
    break;

  case 129:
#line 934 "sql_yacc.yy"
    {yyval.num = (int) STRING_RESULT; }
    break;

  case 130:
#line 935 "sql_yacc.yy"
    {yyval.num = (int) REAL_RESULT; }
    break;

  case 131:
#line 936 "sql_yacc.yy"
    {yyval.num = (int) INT_RESULT; }
    break;

  case 137:
#line 951 "sql_yacc.yy"
    {
	    Lex->col_list.empty();		/* Alloced by sql_alloc */
	  }
    break;

  case 138:
#line 958 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->key_list.push_back(new Key(yyvsp[-4].key_type,yyvsp[-3].simple_string,lex->col_list));
	    lex->col_list.empty();		/* Alloced by sql_alloc */
	  }
    break;

  case 139:
#line 964 "sql_yacc.yy"
    {
	    Lex->col_list.empty();		/* Alloced by sql_alloc */
	  }
    break;

  case 140:
#line 968 "sql_yacc.yy"
    {
	    Lex->col_list.empty();		/* Alloced by sql_alloc */
	  }
    break;

  case 145:
#line 984 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
	   lex->length=lex->dec=0; lex->type=0; lex->interval=0;
	   lex->default_value=0;
	 }
    break;

  case 146:
#line 990 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  if (add_field_to_list(yyvsp[-3].lex_str.str,
				(enum enum_field_types) yyvsp[-1].num,
				lex->length,lex->dec,lex->type,
				lex->default_value,lex->change,
				lex->interval))
	    YYABORT;
	}
    break;

  case 147:
#line 1001 "sql_yacc.yy"
    { Lex->length=yyvsp[-1].simple_string; yyval.num=yyvsp[-2].num; }
    break;

  case 148:
#line 1002 "sql_yacc.yy"
    { yyval.num=yyvsp[-2].num; }
    break;

  case 149:
#line 1003 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_FLOAT; }
    break;

  case 150:
#line 1004 "sql_yacc.yy"
    { Lex->length=(char*) "1";
					  yyval.num=FIELD_TYPE_TINY; }
    break;

  case 151:
#line 1006 "sql_yacc.yy"
    { Lex->length=(char*) "1";
					  yyval.num=FIELD_TYPE_TINY; }
    break;

  case 152:
#line 1008 "sql_yacc.yy"
    { Lex->length=yyvsp[-2].lex_str.str;
					  yyval.num=FIELD_TYPE_STRING; }
    break;

  case 153:
#line 1010 "sql_yacc.yy"
    { Lex->length=(char*) "1";
					  yyval.num=FIELD_TYPE_STRING; }
    break;

  case 154:
#line 1012 "sql_yacc.yy"
    { Lex->length=yyvsp[-1].lex_str.str;
					  Lex->type|=BINARY_FLAG;
					  yyval.num=FIELD_TYPE_STRING; }
    break;

  case 155:
#line 1015 "sql_yacc.yy"
    { Lex->length=yyvsp[-2].lex_str.str;
					  yyval.num=FIELD_TYPE_VAR_STRING; }
    break;

  case 156:
#line 1017 "sql_yacc.yy"
    { Lex->length=yyvsp[-1].lex_str.str;
					  Lex->type|=BINARY_FLAG;
					  yyval.num=FIELD_TYPE_VAR_STRING; }
    break;

  case 157:
#line 1020 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_YEAR; Lex->length=yyvsp[-1].simple_string; }
    break;

  case 158:
#line 1021 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_DATE; }
    break;

  case 159:
#line 1022 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_TIME; }
    break;

  case 160:
#line 1023 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_TIMESTAMP; }
    break;

  case 161:
#line 1024 "sql_yacc.yy"
    { Lex->length=yyvsp[-1].lex_str.str;
					  yyval.num=FIELD_TYPE_TIMESTAMP; }
    break;

  case 162:
#line 1026 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_DATETIME; }
    break;

  case 163:
#line 1027 "sql_yacc.yy"
    { Lex->type|=BINARY_FLAG;
					  yyval.num=FIELD_TYPE_TINY_BLOB; }
    break;

  case 164:
#line 1029 "sql_yacc.yy"
    { Lex->type|=BINARY_FLAG;
					  yyval.num=FIELD_TYPE_BLOB; }
    break;

  case 165:
#line 1031 "sql_yacc.yy"
    { Lex->type|=BINARY_FLAG;
					  yyval.num=FIELD_TYPE_MEDIUM_BLOB; }
    break;

  case 166:
#line 1033 "sql_yacc.yy"
    { Lex->type|=BINARY_FLAG;
					  yyval.num=FIELD_TYPE_LONG_BLOB; }
    break;

  case 167:
#line 1035 "sql_yacc.yy"
    { Lex->type|=BINARY_FLAG;
					  yyval.num=FIELD_TYPE_MEDIUM_BLOB; }
    break;

  case 168:
#line 1037 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_MEDIUM_BLOB; }
    break;

  case 169:
#line 1038 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_TINY_BLOB; }
    break;

  case 170:
#line 1039 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_BLOB; }
    break;

  case 171:
#line 1040 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_MEDIUM_BLOB; }
    break;

  case 172:
#line 1041 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_LONG_BLOB; }
    break;

  case 173:
#line 1043 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_DECIMAL;}
    break;

  case 174:
#line 1045 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_DECIMAL;}
    break;

  case 175:
#line 1046 "sql_yacc.yy"
    {Lex->interval_list.empty();}
    break;

  case 176:
#line 1047 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->interval=typelib(lex->interval_list);
	    yyval.num=FIELD_TYPE_ENUM;
	  }
    break;

  case 177:
#line 1052 "sql_yacc.yy"
    { Lex->interval_list.empty();}
    break;

  case 178:
#line 1053 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->interval=typelib(lex->interval_list);
	    yyval.num=FIELD_TYPE_SET;
	  }
    break;

  case 179:
#line 1060 "sql_yacc.yy"
    {}
    break;

  case 180:
#line 1061 "sql_yacc.yy"
    {}
    break;

  case 181:
#line 1062 "sql_yacc.yy"
    {}
    break;

  case 182:
#line 1065 "sql_yacc.yy"
    {}
    break;

  case 183:
#line 1066 "sql_yacc.yy"
    {}
    break;

  case 184:
#line 1067 "sql_yacc.yy"
    {}
    break;

  case 185:
#line 1068 "sql_yacc.yy"
    {}
    break;

  case 186:
#line 1071 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_LONG; }
    break;

  case 187:
#line 1072 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_TINY; }
    break;

  case 188:
#line 1073 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_SHORT; }
    break;

  case 189:
#line 1074 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_INT24; }
    break;

  case 190:
#line 1075 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_LONGLONG; }
    break;

  case 191:
#line 1078 "sql_yacc.yy"
    { yyval.num= current_thd->sql_mode & MODE_REAL_AS_FLOAT ?
			      FIELD_TYPE_FLOAT : FIELD_TYPE_DOUBLE; }
    break;

  case 192:
#line 1080 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_DOUBLE; }
    break;

  case 193:
#line 1081 "sql_yacc.yy"
    { yyval.num=FIELD_TYPE_DOUBLE; }
    break;

  case 194:
#line 1085 "sql_yacc.yy"
    {}
    break;

  case 195:
#line 1086 "sql_yacc.yy"
    { Lex->length=yyvsp[-1].lex_str.str; }
    break;

  case 196:
#line 1087 "sql_yacc.yy"
    {}
    break;

  case 197:
#line 1091 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->length=yyvsp[-3].lex_str.str; lex->dec=yyvsp[-1].lex_str.str;
	}
    break;

  case 198:
#line 1097 "sql_yacc.yy"
    {}
    break;

  case 199:
#line 1098 "sql_yacc.yy"
    {}
    break;

  case 200:
#line 1101 "sql_yacc.yy"
    {}
    break;

  case 201:
#line 1102 "sql_yacc.yy"
    {}
    break;

  case 202:
#line 1105 "sql_yacc.yy"
    {}
    break;

  case 203:
#line 1106 "sql_yacc.yy"
    { Lex->type|= UNSIGNED_FLAG;}
    break;

  case 204:
#line 1107 "sql_yacc.yy"
    { Lex->type|= UNSIGNED_FLAG | ZEROFILL_FLAG; }
    break;

  case 205:
#line 1110 "sql_yacc.yy"
    { yyval.simple_string=(char*) 0; }
    break;

  case 206:
#line 1111 "sql_yacc.yy"
    { yyval.simple_string=yyvsp[-1].lex_str.str; }
    break;

  case 207:
#line 1114 "sql_yacc.yy"
    {}
    break;

  case 208:
#line 1115 "sql_yacc.yy"
    {}
    break;

  case 209:
#line 1118 "sql_yacc.yy"
    {}
    break;

  case 210:
#line 1119 "sql_yacc.yy"
    {}
    break;

  case 211:
#line 1122 "sql_yacc.yy"
    {}
    break;

  case 213:
#line 1126 "sql_yacc.yy"
    { Lex->type&= ~ NOT_NULL_FLAG; }
    break;

  case 214:
#line 1127 "sql_yacc.yy"
    { Lex->type|= NOT_NULL_FLAG; }
    break;

  case 215:
#line 1128 "sql_yacc.yy"
    { Lex->default_value=yyvsp[0].item; }
    break;

  case 216:
#line 1129 "sql_yacc.yy"
    { Lex->type|= AUTO_INCREMENT_FLAG | NOT_NULL_FLAG; }
    break;

  case 217:
#line 1130 "sql_yacc.yy"
    { Lex->type|= PRI_KEY_FLAG | NOT_NULL_FLAG; }
    break;

  case 218:
#line 1131 "sql_yacc.yy"
    { Lex->type|= UNIQUE_FLAG; }
    break;

  case 219:
#line 1132 "sql_yacc.yy"
    { Lex->type|= UNIQUE_KEY_FLAG; }
    break;

  case 220:
#line 1133 "sql_yacc.yy"
    {}
    break;

  case 221:
#line 1136 "sql_yacc.yy"
    {}
    break;

  case 222:
#line 1137 "sql_yacc.yy"
    { Lex->type|=BINARY_FLAG; }
    break;

  case 223:
#line 1138 "sql_yacc.yy"
    {}
    break;

  case 224:
#line 1142 "sql_yacc.yy"
    {}
    break;

  case 225:
#line 1144 "sql_yacc.yy"
    {
	    Lex->col_list.empty();		/* Alloced by sql_alloc */
	  }
    break;

  case 226:
#line 1149 "sql_yacc.yy"
    {}
    break;

  case 227:
#line 1150 "sql_yacc.yy"
    {}
    break;

  case 228:
#line 1153 "sql_yacc.yy"
    {}
    break;

  case 229:
#line 1154 "sql_yacc.yy"
    {}
    break;

  case 230:
#line 1158 "sql_yacc.yy"
    {}
    break;

  case 231:
#line 1159 "sql_yacc.yy"
    {}
    break;

  case 232:
#line 1160 "sql_yacc.yy"
    {}
    break;

  case 233:
#line 1161 "sql_yacc.yy"
    {}
    break;

  case 234:
#line 1164 "sql_yacc.yy"
    {}
    break;

  case 235:
#line 1165 "sql_yacc.yy"
    {}
    break;

  case 236:
#line 1166 "sql_yacc.yy"
    {}
    break;

  case 237:
#line 1167 "sql_yacc.yy"
    {}
    break;

  case 238:
#line 1168 "sql_yacc.yy"
    {}
    break;

  case 239:
#line 1171 "sql_yacc.yy"
    { yyval.key_type= Key::PRIMARY; }
    break;

  case 240:
#line 1172 "sql_yacc.yy"
    { yyval.key_type= Key::MULTIPLE; }
    break;

  case 241:
#line 1173 "sql_yacc.yy"
    { yyval.key_type= Key::FULLTEXT; }
    break;

  case 242:
#line 1174 "sql_yacc.yy"
    { yyval.key_type= Key::FULLTEXT; }
    break;

  case 243:
#line 1175 "sql_yacc.yy"
    { yyval.key_type= Key::UNIQUE; }
    break;

  case 244:
#line 1176 "sql_yacc.yy"
    { yyval.key_type= Key::UNIQUE; }
    break;

  case 245:
#line 1179 "sql_yacc.yy"
    {}
    break;

  case 246:
#line 1180 "sql_yacc.yy"
    {}
    break;

  case 247:
#line 1183 "sql_yacc.yy"
    {}
    break;

  case 248:
#line 1184 "sql_yacc.yy"
    {}
    break;

  case 249:
#line 1185 "sql_yacc.yy"
    {}
    break;

  case 250:
#line 1188 "sql_yacc.yy"
    { yyval.key_type= Key::MULTIPLE; }
    break;

  case 251:
#line 1189 "sql_yacc.yy"
    { yyval.key_type= Key::UNIQUE; }
    break;

  case 252:
#line 1190 "sql_yacc.yy"
    { yyval.key_type= Key::FULLTEXT; }
    break;

  case 253:
#line 1193 "sql_yacc.yy"
    { Lex->col_list.push_back(yyvsp[-1].key_part); }
    break;

  case 254:
#line 1194 "sql_yacc.yy"
    { Lex->col_list.push_back(yyvsp[-1].key_part); }
    break;

  case 255:
#line 1197 "sql_yacc.yy"
    { yyval.key_part=new key_part_spec(yyvsp[0].lex_str.str); }
    break;

  case 256:
#line 1198 "sql_yacc.yy"
    { yyval.key_part=new key_part_spec(yyvsp[-3].lex_str.str,(uint) atoi(yyvsp[-1].lex_str.str)); }
    break;

  case 257:
#line 1201 "sql_yacc.yy"
    { yyval.simple_string=(char*) 0; }
    break;

  case 258:
#line 1202 "sql_yacc.yy"
    { yyval.simple_string=yyvsp[0].lex_str.str; }
    break;

  case 259:
#line 1205 "sql_yacc.yy"
    { Lex->interval_list.push_back(yyvsp[0].string); }
    break;

  case 260:
#line 1206 "sql_yacc.yy"
    { Lex->interval_list.push_back(yyvsp[0].string); }
    break;

  case 261:
#line 1214 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command = SQLCOM_ALTER_TABLE;
	  lex->name=0;
	  if (!add_table_to_list(yyvsp[0].table, NULL, TL_OPTION_UPDATING))
	    YYABORT;
	  lex->drop_primary=0;
	  lex->create_list.empty();
	  lex->key_list.empty();
	  lex->col_list.empty();
	  lex->drop_list.empty();
	  lex->alter_list.empty();
          lex->select->order_list.elements=0;
          lex->select->order_list.first=0;
          lex->select->order_list.next= (byte**) &lex->select->order_list.first;
	  lex->select->db=lex->name=0;
    	  bzero((char*) &lex->create_info,sizeof(lex->create_info));
	  lex->create_info.db_type= DB_TYPE_DEFAULT;
	  lex->create_info.row_type= ROW_TYPE_NOT_USED;
          lex->alter_keys_onoff=LEAVE_AS_IS;
          lex->simple_alter=1;
	}
    break;

  case 262:
#line 1237 "sql_yacc.yy"
    {}
    break;

  case 266:
#line 1245 "sql_yacc.yy"
    { Lex->change=0; }
    break;

  case 267:
#line 1248 "sql_yacc.yy"
    { Lex->simple_alter=0; }
    break;

  case 268:
#line 1249 "sql_yacc.yy"
    { Lex->simple_alter=0; }
    break;

  case 269:
#line 1250 "sql_yacc.yy"
    { Lex->simple_alter=0; }
    break;

  case 270:
#line 1252 "sql_yacc.yy"
    {
	     LEX *lex=Lex;
	     lex->change= yyvsp[0].lex_str.str; lex->simple_alter=0;
	  }
    break;

  case 272:
#line 1258 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->length=lex->dec=0; lex->type=0; lex->interval=0;
	    lex->default_value=0;
            lex->simple_alter=0;
	  }
    break;

  case 273:
#line 1265 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    if (add_field_to_list(yyvsp[-3].lex_str.str,
				  (enum enum_field_types) yyvsp[-1].num,
				  lex->length,lex->dec,lex->type,
				  lex->default_value, yyvsp[-3].lex_str.str,
				  lex->interval))
	      YYABORT;
	  }
    break;

  case 275:
#line 1276 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->drop_list.push_back(new Alter_drop(Alter_drop::COLUMN,
					    yyvsp[-1].lex_str.str)); lex->simple_alter=0;
	  }
    break;

  case 276:
#line 1282 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->drop_primary=1; lex->simple_alter=0;
	  }
    break;

  case 277:
#line 1286 "sql_yacc.yy"
    { Lex->simple_alter=0; }
    break;

  case 278:
#line 1288 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->drop_list.push_back(new Alter_drop(Alter_drop::KEY,
						    yyvsp[0].lex_str.str));
	    lex->simple_alter=0;
	  }
    break;

  case 279:
#line 1294 "sql_yacc.yy"
    { Lex->alter_keys_onoff=DISABLE; }
    break;

  case 280:
#line 1295 "sql_yacc.yy"
    { Lex->alter_keys_onoff=ENABLE; }
    break;

  case 281:
#line 1297 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->alter_list.push_back(new Alter_column(yyvsp[-3].lex_str.str,yyvsp[0].item));
	    lex->simple_alter=0;
	  }
    break;

  case 282:
#line 1303 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->alter_list.push_back(new Alter_column(yyvsp[-2].lex_str.str,(Item*) 0));
	    lex->simple_alter=0;
	  }
    break;

  case 283:
#line 1309 "sql_yacc.yy"
    { 
	    LEX *lex=Lex;
	    lex->select->db=yyvsp[0].table->db.str;
	    lex->name= yyvsp[0].table->table.str;
	  }
    break;

  case 284:
#line 1314 "sql_yacc.yy"
    { Lex->simple_alter=0; }
    break;

  case 285:
#line 1315 "sql_yacc.yy"
    { Lex->simple_alter=0; }
    break;

  case 286:
#line 1318 "sql_yacc.yy"
    {}
    break;

  case 287:
#line 1319 "sql_yacc.yy"
    {}
    break;

  case 288:
#line 1322 "sql_yacc.yy"
    { Lex->duplicates=DUP_ERROR; }
    break;

  case 289:
#line 1323 "sql_yacc.yy"
    { Lex->duplicates=DUP_IGNORE; }
    break;

  case 290:
#line 1326 "sql_yacc.yy"
    {}
    break;

  case 291:
#line 1327 "sql_yacc.yy"
    {}
    break;

  case 292:
#line 1328 "sql_yacc.yy"
    {}
    break;

  case 293:
#line 1331 "sql_yacc.yy"
    {}
    break;

  case 294:
#line 1332 "sql_yacc.yy"
    { store_position_for_column(yyvsp[0].lex_str.str); }
    break;

  case 295:
#line 1333 "sql_yacc.yy"
    { store_position_for_column(first_keyword); }
    break;

  case 296:
#line 1336 "sql_yacc.yy"
    {}
    break;

  case 297:
#line 1337 "sql_yacc.yy"
    {}
    break;

  case 298:
#line 1338 "sql_yacc.yy"
    {}
    break;

  case 299:
#line 1339 "sql_yacc.yy"
    {}
    break;

  case 300:
#line 1346 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
           lex->sql_command = SQLCOM_SLAVE_START;
	   lex->type = 0;
         }
    break;

  case 301:
#line 1353 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
           lex->sql_command = SQLCOM_SLAVE_STOP;
	   lex->type = 0;
         }
    break;

  case 302:
#line 1360 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
           lex->sql_command = SQLCOM_SLAVE_START;
	   lex->type = 0;
         }
    break;

  case 303:
#line 1367 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
           lex->sql_command = SQLCOM_SLAVE_STOP;
	   lex->type = 0;
         }
    break;

  case 304:
#line 1374 "sql_yacc.yy"
    { Lex->sql_command = SQLCOM_BEGIN;}
    break;

  case 305:
#line 1375 "sql_yacc.yy"
    {}
    break;

  case 308:
#line 1383 "sql_yacc.yy"
    {}
    break;

  case 309:
#line 1384 "sql_yacc.yy"
    { Lex->slave_thd_opt|=SLAVE_SQL; }
    break;

  case 310:
#line 1385 "sql_yacc.yy"
    { Lex->slave_thd_opt|=SLAVE_IO; }
    break;

  case 311:
#line 1390 "sql_yacc.yy"
    {
	   Lex->sql_command = SQLCOM_RESTORE_TABLE;
	}
    break;

  case 312:
#line 1394 "sql_yacc.yy"
    {
	  Lex->backup_dir = yyvsp[0].lex_str.str;
        }
    break;

  case 313:
#line 1400 "sql_yacc.yy"
    {
	   Lex->sql_command = SQLCOM_BACKUP_TABLE;
	}
    break;

  case 314:
#line 1404 "sql_yacc.yy"
    {
	  Lex->backup_dir = yyvsp[0].lex_str.str;
        }
    break;

  case 315:
#line 1410 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
	   lex->sql_command = SQLCOM_REPAIR;
	   lex->check_opt.init();
	}
    break;

  case 316:
#line 1416 "sql_yacc.yy"
    {}
    break;

  case 317:
#line 1420 "sql_yacc.yy"
    { Lex->check_opt.flags = T_MEDIUM; }
    break;

  case 318:
#line 1421 "sql_yacc.yy"
    {}
    break;

  case 319:
#line 1424 "sql_yacc.yy"
    {}
    break;

  case 320:
#line 1425 "sql_yacc.yy"
    {}
    break;

  case 321:
#line 1428 "sql_yacc.yy"
    { Lex->check_opt.flags|= T_QUICK; }
    break;

  case 322:
#line 1429 "sql_yacc.yy"
    { Lex->check_opt.flags|= T_EXTEND; }
    break;

  case 323:
#line 1430 "sql_yacc.yy"
    { Lex->check_opt.sql_flags|= TT_USEFRM; }
    break;

  case 324:
#line 1434 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
	   lex->sql_command = SQLCOM_ANALYZE;
	   lex->check_opt.init();
	}
    break;

  case 325:
#line 1440 "sql_yacc.yy"
    {}
    break;

  case 326:
#line 1445 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
	   lex->sql_command = SQLCOM_CHECK;
	   lex->check_opt.init();
	}
    break;

  case 327:
#line 1451 "sql_yacc.yy"
    {}
    break;

  case 328:
#line 1455 "sql_yacc.yy"
    { Lex->check_opt.flags = T_MEDIUM; }
    break;

  case 329:
#line 1456 "sql_yacc.yy"
    {}
    break;

  case 330:
#line 1459 "sql_yacc.yy"
    {}
    break;

  case 331:
#line 1460 "sql_yacc.yy"
    {}
    break;

  case 332:
#line 1463 "sql_yacc.yy"
    { Lex->check_opt.flags|= T_QUICK; }
    break;

  case 333:
#line 1464 "sql_yacc.yy"
    { Lex->check_opt.flags|= T_FAST; }
    break;

  case 334:
#line 1465 "sql_yacc.yy"
    { Lex->check_opt.flags|= T_MEDIUM; }
    break;

  case 335:
#line 1466 "sql_yacc.yy"
    { Lex->check_opt.flags|= T_EXTEND; }
    break;

  case 336:
#line 1467 "sql_yacc.yy"
    { Lex->check_opt.flags|= T_CHECK_ONLY_CHANGED; }
    break;

  case 337:
#line 1471 "sql_yacc.yy"
    {
	   LEX *lex=Lex;
	   lex->sql_command = SQLCOM_OPTIMIZE;
	   lex->check_opt.init();
	}
    break;

  case 338:
#line 1477 "sql_yacc.yy"
    {}
    break;

  case 339:
#line 1482 "sql_yacc.yy"
    {
	   Lex->sql_command=SQLCOM_RENAME_TABLE;
	}
    break;

  case 340:
#line 1486 "sql_yacc.yy"
    {}
    break;

  case 343:
#line 1495 "sql_yacc.yy"
    {
	   if (!add_table_to_list(yyvsp[-2].table, NULL, TL_OPTION_UPDATING, TL_IGNORE) ||
	       !add_table_to_list(yyvsp[0].table, NULL, TL_OPTION_UPDATING, TL_IGNORE))
	     YYABORT;
 	}
    break;

  case 344:
#line 1507 "sql_yacc.yy"
    { Lex->sql_command=SQLCOM_SELECT; }
    break;

  case 345:
#line 1510 "sql_yacc.yy"
    { Select->braces= 0;	}
    break;

  case 347:
#line 1512 "sql_yacc.yy"
    { Select->braces= 1;}
    break;

  case 349:
#line 1516 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->lock_option=TL_READ;
	   mysql_init_select(lex);
	}
    break;

  case 351:
#line 1524 "sql_yacc.yy"
    {}
    break;

  case 360:
#line 1542 "sql_yacc.yy"
    { Select->options|= SELECT_STRAIGHT_JOIN; }
    break;

  case 361:
#line 1544 "sql_yacc.yy"
    {
	    if (check_simple_select())
	      YYABORT;
	    Lex->lock_option= TL_READ_HIGH_PRIORITY;
	  }
    break;

  case 362:
#line 1549 "sql_yacc.yy"
    { Select->options|= SELECT_DISTINCT; }
    break;

  case 363:
#line 1550 "sql_yacc.yy"
    { Select->options|= SELECT_SMALL_RESULT; }
    break;

  case 364:
#line 1551 "sql_yacc.yy"
    { Select->options|= SELECT_BIG_RESULT; }
    break;

  case 365:
#line 1553 "sql_yacc.yy"
    {
	    if (check_simple_select())
	      YYABORT;
	    Select->options|= OPTION_BUFFER_RESULT;
	  }
    break;

  case 366:
#line 1559 "sql_yacc.yy"
    {
	    if (check_simple_select())
	      YYABORT;
	    Select->options|= OPTION_FOUND_ROWS;
	  }
    break;

  case 367:
#line 1564 "sql_yacc.yy"
    { current_thd->safe_to_cache_query=0; }
    break;

  case 368:
#line 1566 "sql_yacc.yy"
    {
	    Lex->select_lex.options|= OPTION_TO_QUERY_CACHE;
	  }
    break;

  case 369:
#line 1569 "sql_yacc.yy"
    {}
    break;

  case 371:
#line 1575 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    if (check_simple_select())
	      YYABORT;	
	    lex->lock_option= TL_WRITE;
	    lex->thd->safe_to_cache_query=0;
	  }
    break;

  case 372:
#line 1583 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    if (check_simple_select())
	      YYABORT;	
	    lex->lock_option= TL_READ_WITH_SHARED_LOCKS;
	    lex->thd->safe_to_cache_query=0;
	  }
    break;

  case 375:
#line 1596 "sql_yacc.yy"
    {
	    if (add_item_to_list(new Item_field(NULL,NULL,"*")))
	      YYABORT;
	  }
    break;

  case 376:
#line 1604 "sql_yacc.yy"
    {
	    if (add_item_to_list(yyvsp[-2].item))
	      YYABORT;
	    if (yyvsp[0].lex_str.str)
	      yyvsp[-2].item->set_name(yyvsp[0].lex_str.str);
	    else if (!yyvsp[-2].item->name)
	      yyvsp[-2].item->set_name(yyvsp[-3].simple_string,(uint) (yyvsp[-1].simple_string - yyvsp[-3].simple_string));
	  }
    break;

  case 377:
#line 1614 "sql_yacc.yy"
    { yyval.simple_string=(char*) Lex->tok_start; }
    break;

  case 378:
#line 1617 "sql_yacc.yy"
    { yyval.simple_string=(char*) Lex->tok_end; }
    break;

  case 379:
#line 1620 "sql_yacc.yy"
    { yyval.item=yyvsp[0].item; }
    break;

  case 380:
#line 1621 "sql_yacc.yy"
    { yyval.item=yyvsp[0].item; }
    break;

  case 381:
#line 1624 "sql_yacc.yy"
    { yyval.lex_str.str=0;}
    break;

  case 382:
#line 1625 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str; }
    break;

  case 383:
#line 1626 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str; }
    break;

  case 384:
#line 1627 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str; }
    break;

  case 385:
#line 1628 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str; }
    break;

  case 386:
#line 1631 "sql_yacc.yy"
    {}
    break;

  case 387:
#line 1632 "sql_yacc.yy"
    {}
    break;

  case 388:
#line 1635 "sql_yacc.yy"
    {yyval.item = yyvsp[0].item; }
    break;

  case 389:
#line 1636 "sql_yacc.yy"
    {yyval.item = yyvsp[0].item; }
    break;

  case 390:
#line 1641 "sql_yacc.yy"
    { yyval.item= new Item_func_in(yyvsp[-4].item,*yyvsp[-1].item_list); }
    break;

  case 391:
#line 1643 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_in(yyvsp[-5].item,*yyvsp[-1].item_list)); }
    break;

  case 392:
#line 1645 "sql_yacc.yy"
    { yyval.item= new Item_func_between(yyvsp[-4].item,yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 393:
#line 1647 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_between(yyvsp[-5].item,yyvsp[-2].item,yyvsp[0].item)); }
    break;

  case 394:
#line 1648 "sql_yacc.yy"
    { yyval.item= or_or_concat(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 395:
#line 1649 "sql_yacc.yy"
    { yyval.item= new Item_cond_or(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 396:
#line 1650 "sql_yacc.yy"
    { yyval.item= new Item_cond_xor(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 397:
#line 1651 "sql_yacc.yy"
    { yyval.item= new Item_cond_and(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 398:
#line 1652 "sql_yacc.yy"
    { yyval.item= new Item_func_like(yyvsp[-3].item,yyvsp[-1].item,yyvsp[0].simple_string); }
    break;

  case 399:
#line 1653 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_like(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].simple_string));}
    break;

  case 400:
#line 1654 "sql_yacc.yy"
    { yyval.item= new Item_func_regex(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 401:
#line 1655 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_regex(yyvsp[-3].item,yyvsp[0].item)); }
    break;

  case 402:
#line 1656 "sql_yacc.yy"
    { yyval.item= new Item_func_isnull(yyvsp[-2].item); }
    break;

  case 403:
#line 1657 "sql_yacc.yy"
    { yyval.item= new Item_func_isnotnull(yyvsp[-3].item); }
    break;

  case 404:
#line 1658 "sql_yacc.yy"
    { yyval.item= new Item_func_eq(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 405:
#line 1659 "sql_yacc.yy"
    { yyval.item= new Item_func_equal(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 406:
#line 1660 "sql_yacc.yy"
    { yyval.item= new Item_func_ge(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 407:
#line 1661 "sql_yacc.yy"
    { yyval.item= new Item_func_gt(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 408:
#line 1662 "sql_yacc.yy"
    { yyval.item= new Item_func_le(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 409:
#line 1663 "sql_yacc.yy"
    { yyval.item= new Item_func_lt(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 410:
#line 1664 "sql_yacc.yy"
    { yyval.item= new Item_func_ne(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 411:
#line 1665 "sql_yacc.yy"
    { yyval.item= new Item_func_shift_left(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 412:
#line 1666 "sql_yacc.yy"
    { yyval.item= new Item_func_shift_right(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 413:
#line 1667 "sql_yacc.yy"
    { yyval.item= new Item_func_plus(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 414:
#line 1668 "sql_yacc.yy"
    { yyval.item= new Item_func_minus(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 415:
#line 1669 "sql_yacc.yy"
    { yyval.item= new Item_func_mul(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 416:
#line 1670 "sql_yacc.yy"
    { yyval.item= new Item_func_div(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 417:
#line 1671 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_or(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 418:
#line 1672 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_xor(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 419:
#line 1673 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_and(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 420:
#line 1674 "sql_yacc.yy"
    { yyval.item= new Item_func_mod(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 421:
#line 1676 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].interval,0); }
    break;

  case 422:
#line 1678 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].interval,1); }
    break;

  case 423:
#line 1683 "sql_yacc.yy"
    { yyval.item= new Item_func_between(yyvsp[-4].item,yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 424:
#line 1685 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_between(yyvsp[-5].item,yyvsp[-2].item,yyvsp[0].item)); }
    break;

  case 425:
#line 1686 "sql_yacc.yy"
    { yyval.item= or_or_concat(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 426:
#line 1687 "sql_yacc.yy"
    { yyval.item= new Item_cond_or(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 427:
#line 1688 "sql_yacc.yy"
    { yyval.item= new Item_cond_xor(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 428:
#line 1689 "sql_yacc.yy"
    { yyval.item= new Item_cond_and(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 429:
#line 1690 "sql_yacc.yy"
    { yyval.item= new Item_func_like(yyvsp[-3].item,yyvsp[-1].item,yyvsp[0].simple_string); }
    break;

  case 430:
#line 1691 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_like(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].simple_string)); }
    break;

  case 431:
#line 1692 "sql_yacc.yy"
    { yyval.item= new Item_func_regex(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 432:
#line 1693 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_regex(yyvsp[-3].item,yyvsp[0].item)); }
    break;

  case 433:
#line 1694 "sql_yacc.yy"
    { yyval.item= new Item_func_isnull(yyvsp[-2].item); }
    break;

  case 434:
#line 1695 "sql_yacc.yy"
    { yyval.item= new Item_func_isnotnull(yyvsp[-3].item); }
    break;

  case 435:
#line 1696 "sql_yacc.yy"
    { yyval.item= new Item_func_eq(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 436:
#line 1697 "sql_yacc.yy"
    { yyval.item= new Item_func_equal(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 437:
#line 1698 "sql_yacc.yy"
    { yyval.item= new Item_func_ge(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 438:
#line 1699 "sql_yacc.yy"
    { yyval.item= new Item_func_gt(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 439:
#line 1700 "sql_yacc.yy"
    { yyval.item= new Item_func_le(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 440:
#line 1701 "sql_yacc.yy"
    { yyval.item= new Item_func_lt(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 441:
#line 1702 "sql_yacc.yy"
    { yyval.item= new Item_func_ne(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 442:
#line 1703 "sql_yacc.yy"
    { yyval.item= new Item_func_shift_left(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 443:
#line 1704 "sql_yacc.yy"
    { yyval.item= new Item_func_shift_right(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 444:
#line 1705 "sql_yacc.yy"
    { yyval.item= new Item_func_plus(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 445:
#line 1706 "sql_yacc.yy"
    { yyval.item= new Item_func_minus(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 446:
#line 1707 "sql_yacc.yy"
    { yyval.item= new Item_func_mul(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 447:
#line 1708 "sql_yacc.yy"
    { yyval.item= new Item_func_div(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 448:
#line 1709 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_or(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 449:
#line 1710 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_xor(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 450:
#line 1711 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_and(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 451:
#line 1712 "sql_yacc.yy"
    { yyval.item= new Item_func_mod(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 452:
#line 1714 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].interval,0); }
    break;

  case 453:
#line 1716 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].interval,1); }
    break;

  case 455:
#line 1722 "sql_yacc.yy"
    { yyval.item= new Item_func_in(yyvsp[-4].item,*yyvsp[-1].item_list); }
    break;

  case 456:
#line 1724 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_in(yyvsp[-5].item,*yyvsp[-1].item_list)); }
    break;

  case 457:
#line 1726 "sql_yacc.yy"
    { yyval.item= new Item_func_between(yyvsp[-4].item,yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 458:
#line 1728 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_between(yyvsp[-5].item,yyvsp[-2].item,yyvsp[0].item)); }
    break;

  case 459:
#line 1729 "sql_yacc.yy"
    { yyval.item= or_or_concat(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 460:
#line 1730 "sql_yacc.yy"
    { yyval.item= new Item_cond_or(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 461:
#line 1731 "sql_yacc.yy"
    { yyval.item= new Item_cond_xor(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 462:
#line 1732 "sql_yacc.yy"
    { yyval.item= new Item_func_like(yyvsp[-3].item,yyvsp[-1].item,yyvsp[0].simple_string); }
    break;

  case 463:
#line 1733 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_like(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].simple_string)); }
    break;

  case 464:
#line 1734 "sql_yacc.yy"
    { yyval.item= new Item_func_regex(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 465:
#line 1735 "sql_yacc.yy"
    { yyval.item= new Item_func_not(new Item_func_regex(yyvsp[-3].item,yyvsp[0].item)); }
    break;

  case 466:
#line 1736 "sql_yacc.yy"
    { yyval.item= new Item_func_isnull(yyvsp[-2].item); }
    break;

  case 467:
#line 1737 "sql_yacc.yy"
    { yyval.item= new Item_func_isnotnull(yyvsp[-3].item); }
    break;

  case 468:
#line 1738 "sql_yacc.yy"
    { yyval.item= new Item_func_eq(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 469:
#line 1739 "sql_yacc.yy"
    { yyval.item= new Item_func_equal(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 470:
#line 1740 "sql_yacc.yy"
    { yyval.item= new Item_func_ge(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 471:
#line 1741 "sql_yacc.yy"
    { yyval.item= new Item_func_gt(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 472:
#line 1742 "sql_yacc.yy"
    { yyval.item= new Item_func_le(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 473:
#line 1743 "sql_yacc.yy"
    { yyval.item= new Item_func_lt(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 474:
#line 1744 "sql_yacc.yy"
    { yyval.item= new Item_func_ne(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 475:
#line 1745 "sql_yacc.yy"
    { yyval.item= new Item_func_shift_left(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 476:
#line 1746 "sql_yacc.yy"
    { yyval.item= new Item_func_shift_right(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 477:
#line 1747 "sql_yacc.yy"
    { yyval.item= new Item_func_plus(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 478:
#line 1748 "sql_yacc.yy"
    { yyval.item= new Item_func_minus(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 479:
#line 1749 "sql_yacc.yy"
    { yyval.item= new Item_func_mul(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 480:
#line 1750 "sql_yacc.yy"
    { yyval.item= new Item_func_div(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 481:
#line 1751 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_or(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 482:
#line 1752 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_xor(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 483:
#line 1753 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_and(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 484:
#line 1754 "sql_yacc.yy"
    { yyval.item= new Item_func_mod(yyvsp[-2].item,yyvsp[0].item); }
    break;

  case 485:
#line 1756 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].interval,0); }
    break;

  case 486:
#line 1758 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[-4].item,yyvsp[-1].item,yyvsp[0].interval,1); }
    break;

  case 490:
#line 1765 "sql_yacc.yy"
    {
	    yyval.item= new Item_func_set_user_var(yyvsp[-2].lex_str,yyvsp[0].item);
	    current_thd->safe_to_cache_query=0;
	  }
    break;

  case 491:
#line 1770 "sql_yacc.yy"
    {
	    yyval.item= new Item_func_get_user_var(yyvsp[0].lex_str);
	    current_thd->safe_to_cache_query=0;
	  }
    break;

  case 492:
#line 1775 "sql_yacc.yy"
    {
	    if (!(yyval.item= get_system_var((enum_var_type) yyvsp[-1].num, yyvsp[0].lex_str)))
	      YYABORT;
	  }
    break;

  case 494:
#line 1780 "sql_yacc.yy"
    { yyval.item= new Item_func_neg(yyvsp[0].item); }
    break;

  case 495:
#line 1781 "sql_yacc.yy"
    { yyval.item= new Item_func_bit_neg(yyvsp[0].item); }
    break;

  case 496:
#line 1782 "sql_yacc.yy"
    { yyval.item= new Item_func_not(yyvsp[0].item); }
    break;

  case 497:
#line 1783 "sql_yacc.yy"
    { yyval.item= new Item_func_not(yyvsp[0].item); }
    break;

  case 498:
#line 1784 "sql_yacc.yy"
    { yyval.item= yyvsp[-1].item; }
    break;

  case 499:
#line 1785 "sql_yacc.yy"
    { yyval.item= yyvsp[-1].item; }
    break;

  case 500:
#line 1787 "sql_yacc.yy"
    { Select->ftfunc_list.push_back((Item_func_match *)
                   (yyval.item=new Item_func_match_nl(*yyvsp[-4].item_list,yyvsp[-1].item))); }
    break;

  case 501:
#line 1790 "sql_yacc.yy"
    { Select->ftfunc_list.push_back((Item_func_match *)
                   (yyval.item=new Item_func_match_bool(*yyvsp[-7].item_list,yyvsp[-4].item))); }
    break;

  case 502:
#line 1792 "sql_yacc.yy"
    { yyval.item= new Item_func_binary(yyvsp[0].item); }
    break;

  case 503:
#line 1793 "sql_yacc.yy"
    { yyval.item= create_func_cast(yyvsp[-3].item, yyvsp[-1].cast_type); }
    break;

  case 504:
#line 1795 "sql_yacc.yy"
    { yyval.item= new Item_func_case(* yyvsp[-2].item_list, yyvsp[-4].item, yyvsp[-1].item ); }
    break;

  case 505:
#line 1796 "sql_yacc.yy"
    { yyval.item= create_func_cast(yyvsp[-3].item, yyvsp[-1].cast_type); }
    break;

  case 506:
#line 1798 "sql_yacc.yy"
    { yyval.item= ((Item*(*)(void))(yyvsp[-2].symbol.symbol->create_func))();}
    break;

  case 507:
#line 1800 "sql_yacc.yy"
    { yyval.item= ((Item*(*)(Item*))(yyvsp[-3].symbol.symbol->create_func))(yyvsp[-1].item);}
    break;

  case 508:
#line 1802 "sql_yacc.yy"
    { yyval.item= ((Item*(*)(Item*,Item*))(yyvsp[-5].symbol.symbol->create_func))(yyvsp[-3].item,yyvsp[-1].item);}
    break;

  case 509:
#line 1804 "sql_yacc.yy"
    { yyval.item= ((Item*(*)(Item*,Item*,Item*))(yyvsp[-7].symbol.symbol->create_func))(yyvsp[-5].item,yyvsp[-3].item,yyvsp[-1].item);}
    break;

  case 510:
#line 1806 "sql_yacc.yy"
    { yyval.item= new Item_func_atan(yyvsp[-1].item); }
    break;

  case 511:
#line 1808 "sql_yacc.yy"
    { yyval.item= new Item_func_atan(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 512:
#line 1810 "sql_yacc.yy"
    { yyval.item= new Item_func_char(*yyvsp[-1].item_list); }
    break;

  case 513:
#line 1812 "sql_yacc.yy"
    { yyval.item= new Item_func_coalesce(* yyvsp[-1].item_list); }
    break;

  case 514:
#line 1814 "sql_yacc.yy"
    { yyval.item= new Item_func_concat(* yyvsp[-1].item_list); }
    break;

  case 515:
#line 1816 "sql_yacc.yy"
    { yyval.item= new Item_func_concat_ws(yyvsp[-3].item, *yyvsp[-1].item_list); }
    break;

  case 516:
#line 1818 "sql_yacc.yy"
    { yyval.item= new Item_func_curdate(); current_thd->safe_to_cache_query=0; }
    break;

  case 517:
#line 1820 "sql_yacc.yy"
    { yyval.item= new Item_func_curtime(); current_thd->safe_to_cache_query=0; }
    break;

  case 518:
#line 1822 "sql_yacc.yy"
    { 
	    yyval.item= new Item_func_curtime(yyvsp[-1].item); 
	    current_thd->safe_to_cache_query=0;
	  }
    break;

  case 519:
#line 1827 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[-5].item,yyvsp[-2].item,yyvsp[-1].interval,0); }
    break;

  case 520:
#line 1829 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[-5].item,yyvsp[-2].item,yyvsp[-1].interval,1); }
    break;

  case 521:
#line 1831 "sql_yacc.yy"
    { 
	    yyval.item= new Item_func_database();
            current_thd->safe_to_cache_query=0; 
	  }
    break;

  case 522:
#line 1836 "sql_yacc.yy"
    { yyval.item= new Item_func_elt(yyvsp[-3].item, *yyvsp[-1].item_list); }
    break;

  case 523:
#line 1838 "sql_yacc.yy"
    { yyval.item= new Item_func_make_set(yyvsp[-3].item, *yyvsp[-1].item_list); }
    break;

  case 524:
#line 1840 "sql_yacc.yy"
    {
	    yyval.item= new Item_func_encrypt(yyvsp[-1].item);
	    current_thd->safe_to_cache_query=0; 
	  }
    break;

  case 525:
#line 1844 "sql_yacc.yy"
    { yyval.item= new Item_func_encrypt(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 526:
#line 1846 "sql_yacc.yy"
    { yyval.item= new Item_func_decode(yyvsp[-3].item,yyvsp[-1].lex_str.str); }
    break;

  case 527:
#line 1848 "sql_yacc.yy"
    { yyval.item= new Item_func_encode(yyvsp[-3].item,yyvsp[-1].lex_str.str); }
    break;

  case 528:
#line 1850 "sql_yacc.yy"
    { yyval.item= new Item_func_des_decrypt(yyvsp[-1].item); }
    break;

  case 529:
#line 1852 "sql_yacc.yy"
    { yyval.item= new Item_func_des_decrypt(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 530:
#line 1854 "sql_yacc.yy"
    { yyval.item= new Item_func_des_encrypt(yyvsp[-1].item); }
    break;

  case 531:
#line 1856 "sql_yacc.yy"
    { yyval.item= new Item_func_des_encrypt(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 532:
#line 1858 "sql_yacc.yy"
    { yyval.item= new Item_func_export_set(yyvsp[-5].item, yyvsp[-3].item, yyvsp[-1].item); }
    break;

  case 533:
#line 1860 "sql_yacc.yy"
    { yyval.item= new Item_func_export_set(yyvsp[-7].item, yyvsp[-5].item, yyvsp[-3].item, yyvsp[-1].item); }
    break;

  case 534:
#line 1862 "sql_yacc.yy"
    { yyval.item= new Item_func_export_set(yyvsp[-9].item, yyvsp[-7].item, yyvsp[-5].item, yyvsp[-3].item, yyvsp[-1].item); }
    break;

  case 535:
#line 1864 "sql_yacc.yy"
    { yyval.item= new Item_func_format(yyvsp[-3].item,atoi(yyvsp[-1].lex_str.str)); }
    break;

  case 536:
#line 1866 "sql_yacc.yy"
    { yyval.item= new Item_func_from_unixtime(yyvsp[-1].item); }
    break;

  case 537:
#line 1868 "sql_yacc.yy"
    {
	    yyval.item= new Item_func_date_format (new Item_func_from_unixtime(yyvsp[-3].item),yyvsp[-1].item,0);
	  }
    break;

  case 538:
#line 1872 "sql_yacc.yy"
    { yyval.item= new Item_func_field(yyvsp[-3].item, *yyvsp[-1].item_list); }
    break;

  case 539:
#line 1874 "sql_yacc.yy"
    { yyval.item= new Item_func_hour(yyvsp[-1].item); }
    break;

  case 540:
#line 1876 "sql_yacc.yy"
    { yyval.item= new Item_func_if(yyvsp[-5].item,yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 541:
#line 1878 "sql_yacc.yy"
    { yyval.item= new Item_func_insert(yyvsp[-7].item,yyvsp[-5].item,yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 542:
#line 1881 "sql_yacc.yy"
    { yyval.item= new Item_date_add_interval(yyvsp[0].item,yyvsp[-3].item,yyvsp[-2].interval,0); }
    break;

  case 543:
#line 1883 "sql_yacc.yy"
    { yyval.item= new Item_func_interval(yyvsp[-3].item,* yyvsp[-1].item_list); }
    break;

  case 544:
#line 1885 "sql_yacc.yy"
    {
	    yyval.item= new Item_int((char*) "last_insert_id()",
			     current_thd->insert_id(),21);
	    current_thd->safe_to_cache_query=0;
	  }
    break;

  case 545:
#line 1891 "sql_yacc.yy"
    {
	    yyval.item= new Item_func_set_last_insert_id(yyvsp[-1].item);
	    current_thd->safe_to_cache_query=0;
	  }
    break;

  case 546:
#line 1896 "sql_yacc.yy"
    { yyval.item= new Item_func_left(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 547:
#line 1898 "sql_yacc.yy"
    { yyval.item= new Item_func_locate(yyvsp[-1].item,yyvsp[-3].item); }
    break;

  case 548:
#line 1900 "sql_yacc.yy"
    { yyval.item= new Item_func_locate(yyvsp[-3].item,yyvsp[-5].item,yyvsp[-1].item); }
    break;

  case 549:
#line 1902 "sql_yacc.yy"
    { yyvsp[-1].item_list->push_front(yyvsp[-3].item); yyval.item= new Item_func_max(*yyvsp[-1].item_list); }
    break;

  case 550:
#line 1904 "sql_yacc.yy"
    { yyvsp[-1].item_list->push_front(yyvsp[-3].item); yyval.item= new Item_func_min(*yyvsp[-1].item_list); }
    break;

  case 551:
#line 1906 "sql_yacc.yy"
    { yyval.item= new Item_func_log(yyvsp[-1].item); }
    break;

  case 552:
#line 1908 "sql_yacc.yy"
    { yyval.item= new Item_func_log(yyvsp[-3].item, yyvsp[-1].item); }
    break;

  case 553:
#line 1910 "sql_yacc.yy"
    { 
	    yyval.item= new Item_master_pos_wait(yyvsp[-3].item, yyvsp[-1].item);
	    current_thd->safe_to_cache_query=0; 
	  }
    break;

  case 554:
#line 1915 "sql_yacc.yy"
    { 
	    yyval.item= new Item_master_pos_wait(yyvsp[-5].item, yyvsp[-3].item, yyvsp[-1].item);
	    current_thd->safe_to_cache_query=0; 
	  }
    break;

  case 555:
#line 1920 "sql_yacc.yy"
    { yyval.item= new Item_func_minute(yyvsp[-1].item); }
    break;

  case 556:
#line 1922 "sql_yacc.yy"
    { yyval.item= new Item_func_month(yyvsp[-1].item); }
    break;

  case 557:
#line 1924 "sql_yacc.yy"
    { yyval.item= new Item_func_now(); current_thd->safe_to_cache_query=0;}
    break;

  case 558:
#line 1926 "sql_yacc.yy"
    { yyval.item= new Item_func_now(yyvsp[-1].item); current_thd->safe_to_cache_query=0;}
    break;

  case 559:
#line 1928 "sql_yacc.yy"
    {
	    yyval.item= new Item_func_password(yyvsp[-1].item);
	   }
    break;

  case 560:
#line 1932 "sql_yacc.yy"
    { yyval.item = new Item_func_locate(yyvsp[-1].item,yyvsp[-3].item); }
    break;

  case 561:
#line 1934 "sql_yacc.yy"
    { yyval.item= new Item_func_rand(yyvsp[-1].item); current_thd->safe_to_cache_query=0;}
    break;

  case 562:
#line 1936 "sql_yacc.yy"
    { yyval.item= new Item_func_rand(); current_thd->safe_to_cache_query=0;}
    break;

  case 563:
#line 1938 "sql_yacc.yy"
    { yyval.item= new Item_func_replace(yyvsp[-5].item,yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 564:
#line 1940 "sql_yacc.yy"
    { yyval.item= new Item_func_right(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 565:
#line 1942 "sql_yacc.yy"
    { yyval.item= new Item_func_round(yyvsp[-1].item, new Item_int((char*)"0",0,1),0); }
    break;

  case 566:
#line 1943 "sql_yacc.yy"
    { yyval.item= new Item_func_round(yyvsp[-3].item,yyvsp[-1].item,0); }
    break;

  case 567:
#line 1945 "sql_yacc.yy"
    { yyval.item= new Item_func_second(yyvsp[-1].item); }
    break;

  case 568:
#line 1947 "sql_yacc.yy"
    { yyval.item= new Item_func_substr(yyvsp[-5].item,yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 569:
#line 1949 "sql_yacc.yy"
    { yyval.item= new Item_func_substr(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 570:
#line 1951 "sql_yacc.yy"
    { yyval.item= new Item_func_substr(yyvsp[-5].item,yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 571:
#line 1953 "sql_yacc.yy"
    { yyval.item= new Item_func_substr(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 572:
#line 1955 "sql_yacc.yy"
    { yyval.item= new Item_func_substr_index(yyvsp[-5].item,yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 573:
#line 1957 "sql_yacc.yy"
    { yyval.item= new Item_func_trim(yyvsp[-1].item,new Item_string(" ",1)); }
    break;

  case 574:
#line 1959 "sql_yacc.yy"
    { yyval.item= new Item_func_ltrim(yyvsp[-1].item,yyvsp[-3].item); }
    break;

  case 575:
#line 1961 "sql_yacc.yy"
    { yyval.item= new Item_func_rtrim(yyvsp[-1].item,yyvsp[-3].item); }
    break;

  case 576:
#line 1963 "sql_yacc.yy"
    { yyval.item= new Item_func_trim(yyvsp[-1].item,yyvsp[-3].item); }
    break;

  case 577:
#line 1965 "sql_yacc.yy"
    { yyval.item= new Item_func_trim(yyvsp[-1].item,yyvsp[-3].item); }
    break;

  case 578:
#line 1967 "sql_yacc.yy"
    { yyval.item= new Item_func_round(yyvsp[-3].item,yyvsp[-1].item,1); }
    break;

  case 579:
#line 1969 "sql_yacc.yy"
    {
	    if (yyvsp[-1].item_list != NULL)
	      yyval.item = new Item_sum_udf_str(yyvsp[-3].udf, *yyvsp[-1].item_list);
	    else
	      yyval.item = new Item_sum_udf_str(yyvsp[-3].udf);
	  }
    break;

  case 580:
#line 1976 "sql_yacc.yy"
    {
	    if (yyvsp[-1].item_list != NULL)
	      yyval.item = new Item_sum_udf_float(yyvsp[-3].udf, *yyvsp[-1].item_list);
	    else
	      yyval.item = new Item_sum_udf_float(yyvsp[-3].udf);
	  }
    break;

  case 581:
#line 1983 "sql_yacc.yy"
    {
	    if (yyvsp[-1].item_list != NULL)
	      yyval.item = new Item_sum_udf_int(yyvsp[-3].udf, *yyvsp[-1].item_list);
	    else
	      yyval.item = new Item_sum_udf_int(yyvsp[-3].udf);
	  }
    break;

  case 582:
#line 1990 "sql_yacc.yy"
    {
	    if (yyvsp[-1].item_list != NULL)
	      yyval.item = new Item_func_udf_str(yyvsp[-3].udf, *yyvsp[-1].item_list);
	    else
	      yyval.item = new Item_func_udf_str(yyvsp[-3].udf);
	  }
    break;

  case 583:
#line 1997 "sql_yacc.yy"
    {
	    if (yyvsp[-1].item_list != NULL)
	      yyval.item = new Item_func_udf_float(yyvsp[-3].udf, *yyvsp[-1].item_list);
	    else
	      yyval.item = new Item_func_udf_float(yyvsp[-3].udf);
	  }
    break;

  case 584:
#line 2004 "sql_yacc.yy"
    {
	    if (yyvsp[-1].item_list != NULL)
	      yyval.item = new Item_func_udf_int(yyvsp[-3].udf, *yyvsp[-1].item_list);
	    else
	      yyval.item = new Item_func_udf_int(yyvsp[-3].udf);
	  }
    break;

  case 585:
#line 2011 "sql_yacc.yy"
    { 
            yyval.item= new Item_func_unique_users(yyvsp[-7].item,atoi(yyvsp[-5].lex_str.str),atoi(yyvsp[-3].lex_str.str), * yyvsp[-1].item_list);
	  }
    break;

  case 586:
#line 2015 "sql_yacc.yy"
    {
	    yyval.item= new Item_func_unix_timestamp();
	    current_thd->safe_to_cache_query=0;
	  }
    break;

  case 587:
#line 2020 "sql_yacc.yy"
    { yyval.item= new Item_func_unix_timestamp(yyvsp[-1].item); }
    break;

  case 588:
#line 2022 "sql_yacc.yy"
    { yyval.item= new Item_func_user(); current_thd->safe_to_cache_query=0; }
    break;

  case 589:
#line 2024 "sql_yacc.yy"
    { 
	    LEX *lex=Lex;
	    yyval.item= new Item_func_week(yyvsp[-1].item,new Item_int((char*) "0", 
                                   lex->thd->variables.default_week_format,1));
	  }
    break;

  case 590:
#line 2030 "sql_yacc.yy"
    { yyval.item= new Item_func_week(yyvsp[-3].item,yyvsp[-1].item); }
    break;

  case 591:
#line 2032 "sql_yacc.yy"
    { yyval.item= new Item_func_year(yyvsp[-1].item); }
    break;

  case 592:
#line 2034 "sql_yacc.yy"
    { yyval.item= new Item_func_yearweek(yyvsp[-1].item,new Item_int((char*) "0",0,1)); }
    break;

  case 593:
#line 2036 "sql_yacc.yy"
    { yyval.item= new Item_func_yearweek(yyvsp[-3].item, yyvsp[-1].item); }
    break;

  case 594:
#line 2038 "sql_yacc.yy"
    { 
	    yyval.item=new Item_func_benchmark(yyvsp[-3].ulong_num,yyvsp[-1].item);
	    current_thd->safe_to_cache_query=0;
	  }
    break;

  case 595:
#line 2043 "sql_yacc.yy"
    { yyval.item=new Item_extract( yyvsp[-3].interval, yyvsp[-1].item); }
    break;

  case 596:
#line 2046 "sql_yacc.yy"
    { yyval.item_list= NULL; }
    break;

  case 597:
#line 2047 "sql_yacc.yy"
    { yyval.item_list= yyvsp[0].item_list;}
    break;

  case 598:
#line 2051 "sql_yacc.yy"
    { yyval.item=new Item_sum_avg(yyvsp[-1].item); }
    break;

  case 599:
#line 2053 "sql_yacc.yy"
    { yyval.item=new Item_sum_and(yyvsp[-1].item); }
    break;

  case 600:
#line 2055 "sql_yacc.yy"
    { yyval.item=new Item_sum_or(yyvsp[-1].item); }
    break;

  case 601:
#line 2057 "sql_yacc.yy"
    { yyval.item=new Item_sum_count(new Item_int((int32) 0L,1)); }
    break;

  case 602:
#line 2059 "sql_yacc.yy"
    { yyval.item=new Item_sum_count(yyvsp[-1].item); }
    break;

  case 603:
#line 2061 "sql_yacc.yy"
    { Select->in_sum_expr++; }
    break;

  case 604:
#line 2063 "sql_yacc.yy"
    { Select->in_sum_expr--; }
    break;

  case 605:
#line 2065 "sql_yacc.yy"
    { yyval.item=new Item_sum_count_distinct(* yyvsp[-2].item_list); }
    break;

  case 606:
#line 2067 "sql_yacc.yy"
    { yyval.item= new Item_sum_unique_users(yyvsp[-7].item,atoi(yyvsp[-5].lex_str.str),atoi(yyvsp[-3].lex_str.str),yyvsp[-1].item); }
    break;

  case 607:
#line 2069 "sql_yacc.yy"
    { yyval.item=new Item_sum_min(yyvsp[-1].item); }
    break;

  case 608:
#line 2071 "sql_yacc.yy"
    { yyval.item=new Item_sum_max(yyvsp[-1].item); }
    break;

  case 609:
#line 2073 "sql_yacc.yy"
    { yyval.item=new Item_sum_std(yyvsp[-1].item); }
    break;

  case 610:
#line 2075 "sql_yacc.yy"
    { yyval.item=new Item_sum_sum(yyvsp[-1].item); }
    break;

  case 611:
#line 2079 "sql_yacc.yy"
    { Select->in_sum_expr++; }
    break;

  case 612:
#line 2081 "sql_yacc.yy"
    {
	  Select->in_sum_expr--;
	  yyval.item=yyvsp[0].item;
	}
    break;

  case 613:
#line 2087 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_BINARY; }
    break;

  case 614:
#line 2088 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_CHAR; }
    break;

  case 615:
#line 2089 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_SIGNED_INT; }
    break;

  case 616:
#line 2090 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_SIGNED_INT; }
    break;

  case 617:
#line 2091 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_UNSIGNED_INT; }
    break;

  case 618:
#line 2092 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_UNSIGNED_INT; }
    break;

  case 619:
#line 2093 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_DATE; }
    break;

  case 620:
#line 2094 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_TIME; }
    break;

  case 621:
#line 2095 "sql_yacc.yy"
    { yyval.cast_type=ITEM_CAST_DATETIME; }
    break;

  case 622:
#line 2099 "sql_yacc.yy"
    { Select->expr_list.push_front(new List<Item>); }
    break;

  case 623:
#line 2101 "sql_yacc.yy"
    { yyval.item_list= Select->expr_list.pop(); }
    break;

  case 624:
#line 2104 "sql_yacc.yy"
    { Select->expr_list.head()->push_back(yyvsp[0].item); }
    break;

  case 625:
#line 2105 "sql_yacc.yy"
    { Select->expr_list.head()->push_back(yyvsp[0].item); }
    break;

  case 626:
#line 2108 "sql_yacc.yy"
    { yyval.item_list= yyvsp[0].item_list; }
    break;

  case 627:
#line 2109 "sql_yacc.yy"
    { yyval.item_list= yyvsp[-1].item_list; }
    break;

  case 628:
#line 2112 "sql_yacc.yy"
    { Select->expr_list.push_front(new List<Item>); }
    break;

  case 629:
#line 2114 "sql_yacc.yy"
    { yyval.item_list= Select->expr_list.pop(); }
    break;

  case 630:
#line 2117 "sql_yacc.yy"
    { Select->expr_list.head()->push_back(yyvsp[0].item); }
    break;

  case 631:
#line 2118 "sql_yacc.yy"
    { Select->expr_list.head()->push_back(yyvsp[0].item); }
    break;

  case 632:
#line 2121 "sql_yacc.yy"
    { yyval.item= NULL; }
    break;

  case 633:
#line 2122 "sql_yacc.yy"
    { yyval.item= yyvsp[0].item; }
    break;

  case 634:
#line 2125 "sql_yacc.yy"
    { yyval.item= NULL; }
    break;

  case 635:
#line 2126 "sql_yacc.yy"
    { yyval.item= yyvsp[0].item; }
    break;

  case 636:
#line 2129 "sql_yacc.yy"
    { Select->when_list.push_front(new List<Item>); }
    break;

  case 637:
#line 2131 "sql_yacc.yy"
    { yyval.item_list= Select->when_list.pop(); }
    break;

  case 638:
#line 2135 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;	    
	    sel->when_list.head()->push_back(yyvsp[-2].item);
	    sel->when_list.head()->push_back(yyvsp[0].item);
	}
    break;

  case 639:
#line 2141 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    sel->when_list.head()->push_back(yyvsp[-2].item);
	    sel->when_list.head()->push_back(yyvsp[0].item);
	  }
    break;

  case 640:
#line 2148 "sql_yacc.yy"
    { yyval.item=new Item_string(" ",1); }
    break;

  case 641:
#line 2149 "sql_yacc.yy"
    { yyval.item=yyvsp[0].item; }
    break;

  case 642:
#line 2152 "sql_yacc.yy"
    { yyval.table_list=yyvsp[-1].table_list; }
    break;

  case 643:
#line 2153 "sql_yacc.yy"
    { yyval.table_list=yyvsp[0].table_list; }
    break;

  case 644:
#line 2154 "sql_yacc.yy"
    { yyval.table_list=yyvsp[0].table_list; }
    break;

  case 645:
#line 2155 "sql_yacc.yy"
    { yyval.table_list=yyvsp[0].table_list; }
    break;

  case 646:
#line 2157 "sql_yacc.yy"
    { yyval.table_list=yyvsp[0].table_list ; yyvsp[-2].table_list->next->straight=1; }
    break;

  case 647:
#line 2159 "sql_yacc.yy"
    { add_join_on(yyvsp[-2].table_list,yyvsp[0].item); yyval.table_list=yyvsp[-2].table_list; }
    break;

  case 648:
#line 2162 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    sel->db1=yyvsp[-3].table_list->db; sel->table1=yyvsp[-3].table_list->alias;
	    sel->db2=yyvsp[-1].table_list->db; sel->table2=yyvsp[-1].table_list->alias;
	  }
    break;

  case 649:
#line 2168 "sql_yacc.yy"
    { add_join_on(yyvsp[-5].table_list,yyvsp[-1].item); yyval.table_list=yyvsp[-5].table_list; }
    break;

  case 650:
#line 2171 "sql_yacc.yy"
    { add_join_on(yyvsp[-2].table_list,yyvsp[0].item); yyvsp[-2].table_list->outer_join|=JOIN_TYPE_LEFT; yyval.table_list=yyvsp[-2].table_list; }
    break;

  case 651:
#line 2173 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    sel->db1=yyvsp[-4].table_list->db; sel->table1=yyvsp[-4].table_list->alias;
	    sel->db2=yyvsp[0].table_list->db; sel->table2=yyvsp[0].table_list->alias;
	  }
    break;

  case 652:
#line 2179 "sql_yacc.yy"
    { add_join_on(yyvsp[-5].table_list,yyvsp[-1].item); yyvsp[-5].table_list->outer_join|=JOIN_TYPE_LEFT; yyval.table_list=yyvsp[-5].table_list; }
    break;

  case 653:
#line 2181 "sql_yacc.yy"
    {
	    add_join_natural(yyvsp[-5].table_list,yyvsp[-5].table_list->next);
	    yyvsp[-5].table_list->next->outer_join|=JOIN_TYPE_LEFT;
	    yyval.table_list=yyvsp[0].table_list;
	  }
    break;

  case 654:
#line 2187 "sql_yacc.yy"
    { add_join_on(yyvsp[-6].table_list,yyvsp[0].item); yyvsp[-6].table_list->outer_join|=JOIN_TYPE_RIGHT; yyval.table_list=yyvsp[-2].table_list; }
    break;

  case 655:
#line 2189 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    sel->db1=yyvsp[-4].table_list->db; sel->table1=yyvsp[-4].table_list->alias;
	    sel->db2=yyvsp[0].table_list->db; sel->table2=yyvsp[0].table_list->alias;
	  }
    break;

  case 656:
#line 2195 "sql_yacc.yy"
    { add_join_on(yyvsp[-9].table_list,yyvsp[-1].item); yyvsp[-9].table_list->outer_join|=JOIN_TYPE_RIGHT; yyval.table_list=yyvsp[-5].table_list; }
    break;

  case 657:
#line 2197 "sql_yacc.yy"
    {
	    add_join_natural(yyvsp[-5].table_list->next,yyvsp[-5].table_list);
	    yyvsp[-5].table_list->outer_join|=JOIN_TYPE_RIGHT;
	    yyval.table_list=yyvsp[0].table_list;
	  }
    break;

  case 658:
#line 2203 "sql_yacc.yy"
    { add_join_natural(yyvsp[-3].table_list,yyvsp[-3].table_list->next); yyval.table_list=yyvsp[0].table_list; }
    break;

  case 659:
#line 2206 "sql_yacc.yy"
    {}
    break;

  case 660:
#line 2207 "sql_yacc.yy"
    {}
    break;

  case 661:
#line 2208 "sql_yacc.yy"
    {}
    break;

  case 662:
#line 2212 "sql_yacc.yy"
    {
	  SELECT_LEX *sel=Select;
	  sel->use_index_ptr=sel->ignore_index_ptr=0;
	  sel->table_join_options= 0;
	}
    break;

  case 663:
#line 2218 "sql_yacc.yy"
    {
	  SELECT_LEX *sel=Select;
	  if (!(yyval.table_list=add_table_to_list(yyvsp[-2].table, yyvsp[-1].lex_str_ptr, sel->table_join_options,
				     TL_UNLOCK, sel->use_index_ptr,
	                             sel->ignore_index_ptr)))
	    YYABORT;
	}
    break;

  case 664:
#line 2226 "sql_yacc.yy"
    { add_join_on(yyvsp[-3].table_list,yyvsp[-1].item); yyvsp[-3].table_list->outer_join|=JOIN_TYPE_LEFT; yyval.table_list=yyvsp[-3].table_list; }
    break;

  case 665:
#line 2229 "sql_yacc.yy"
    {}
    break;

  case 666:
#line 2230 "sql_yacc.yy"
    {}
    break;

  case 667:
#line 2233 "sql_yacc.yy"
    {}
    break;

  case 668:
#line 2235 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    sel->use_index= *yyvsp[0].string_list;
	    sel->use_index_ptr= &sel->use_index;
	  }
    break;

  case 669:
#line 2241 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    sel->use_index= *yyvsp[0].string_list;
	    sel->use_index_ptr= &sel->use_index;
	    sel->table_join_options|= TL_OPTION_FORCE_INDEX;
	  }
    break;

  case 670:
#line 2248 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    sel->ignore_index= *yyvsp[0].string_list;
	    sel->ignore_index_ptr= &sel->ignore_index;
	  }
    break;

  case 671:
#line 2256 "sql_yacc.yy"
    { Select->interval_list.empty(); }
    break;

  case 672:
#line 2257 "sql_yacc.yy"
    { yyval.string_list= &Select->interval_list; }
    break;

  case 673:
#line 2261 "sql_yacc.yy"
    { Select->interval_list.push_back(new String((const char*) yyvsp[0].lex_str.str,yyvsp[0].lex_str.length)); }
    break;

  case 674:
#line 2263 "sql_yacc.yy"
    { Select->interval_list.push_back(new String((const char*) yyvsp[0].lex_str.str,yyvsp[0].lex_str.length)); }
    break;

  case 675:
#line 2265 "sql_yacc.yy"
    { Select->interval_list.push_back(new String("PRIMARY",7)); }
    break;

  case 676:
#line 2269 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    if (!(yyval.item= new Item_func_eq(new Item_field(sel->db1,sel->table1, yyvsp[0].lex_str.str), new Item_field(sel->db2,sel->table2,yyvsp[0].lex_str.str))))
	      YYABORT;
	  }
    break;

  case 677:
#line 2275 "sql_yacc.yy"
    {
	    SELECT_LEX *sel=Select;
	    if (!(yyval.item= new Item_cond_and(new Item_func_eq(new Item_field(sel->db1,sel->table1,yyvsp[0].lex_str.str), new Item_field(sel->db2,sel->table2,yyvsp[0].lex_str.str)), yyvsp[-2].item)))
	      YYABORT;
	  }
    break;

  case 678:
#line 2282 "sql_yacc.yy"
    { yyval.interval=INTERVAL_DAY_HOUR; }
    break;

  case 679:
#line 2283 "sql_yacc.yy"
    { yyval.interval=INTERVAL_DAY_MINUTE; }
    break;

  case 680:
#line 2284 "sql_yacc.yy"
    { yyval.interval=INTERVAL_DAY_SECOND; }
    break;

  case 681:
#line 2285 "sql_yacc.yy"
    { yyval.interval=INTERVAL_DAY; }
    break;

  case 682:
#line 2286 "sql_yacc.yy"
    { yyval.interval=INTERVAL_HOUR_MINUTE; }
    break;

  case 683:
#line 2287 "sql_yacc.yy"
    { yyval.interval=INTERVAL_HOUR_SECOND; }
    break;

  case 684:
#line 2288 "sql_yacc.yy"
    { yyval.interval=INTERVAL_HOUR; }
    break;

  case 685:
#line 2289 "sql_yacc.yy"
    { yyval.interval=INTERVAL_MINUTE_SECOND; }
    break;

  case 686:
#line 2290 "sql_yacc.yy"
    { yyval.interval=INTERVAL_MINUTE; }
    break;

  case 687:
#line 2291 "sql_yacc.yy"
    { yyval.interval=INTERVAL_MONTH; }
    break;

  case 688:
#line 2292 "sql_yacc.yy"
    { yyval.interval=INTERVAL_SECOND; }
    break;

  case 689:
#line 2293 "sql_yacc.yy"
    { yyval.interval=INTERVAL_YEAR_MONTH; }
    break;

  case 690:
#line 2294 "sql_yacc.yy"
    { yyval.interval=INTERVAL_YEAR; }
    break;

  case 694:
#line 2302 "sql_yacc.yy"
    { yyval.lex_str_ptr=0; }
    break;

  case 695:
#line 2304 "sql_yacc.yy"
    { yyval.lex_str_ptr= (LEX_STRING*) sql_memdup(&yyvsp[0].lex_str,sizeof(LEX_STRING)); }
    break;

  case 698:
#line 2312 "sql_yacc.yy"
    { Select->where= 0; }
    break;

  case 699:
#line 2314 "sql_yacc.yy"
    {
	    Select->where= yyvsp[0].item;
	    if (yyvsp[0].item)
	      yyvsp[0].item->top_level_item();
	  }
    break;

  case 701:
#line 2323 "sql_yacc.yy"
    { Select->create_refs=1; }
    break;

  case 702:
#line 2324 "sql_yacc.yy"
    {
	  SELECT_LEX *sel=Select;
	  sel->having= yyvsp[0].item;
	  sel->create_refs=0;
	  if (yyvsp[0].item)
	    yyvsp[0].item->top_level_item();
	}
    break;

  case 703:
#line 2334 "sql_yacc.yy"
    { yyval.simple_string= yyvsp[0].lex_str.str; }
    break;

  case 704:
#line 2335 "sql_yacc.yy"
    { yyval.simple_string= (char*) "\\"; }
    break;

  case 707:
#line 2348 "sql_yacc.yy"
    { if (add_group_to_list(yyvsp[-1].item,(bool) yyvsp[0].num)) YYABORT; }
    break;

  case 708:
#line 2350 "sql_yacc.yy"
    { if (add_group_to_list(yyvsp[-1].item,(bool) yyvsp[0].num)) YYABORT; }
    break;

  case 709:
#line 2353 "sql_yacc.yy"
    {}
    break;

  case 710:
#line 2355 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    net_printf(&lex->thd->net, ER_NOT_SUPPORTED_YET, "CUBE");
	    YYABORT;	/* To be deleted in 4.1 */
	  }
    break;

  case 711:
#line 2361 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    net_printf(&lex->thd->net, ER_NOT_SUPPORTED_YET, "ROLLUP");
	    YYABORT;	/* To be deleted in 4.1 */
	  }
    break;

  case 714:
#line 2378 "sql_yacc.yy"
    { 
	  LEX *lex=Lex;
	  if (lex->select->olap != UNSPECIFIED_OLAP_TYPE)
	  {
	    net_printf(&lex->thd->net, ER_WRONG_USAGE,
		       "CUBE/ROLLUP",
		       "ORDER BY");
	    YYABORT;
	  }
	  lex->select->sort_default=1;
	}
    break;

  case 716:
#line 2392 "sql_yacc.yy"
    { if (add_order_to_list(yyvsp[-1].item,(bool) yyvsp[0].num)) YYABORT; }
    break;

  case 717:
#line 2394 "sql_yacc.yy"
    { if (add_order_to_list(yyvsp[-1].item,(bool) yyvsp[0].num)) YYABORT; }
    break;

  case 718:
#line 2397 "sql_yacc.yy"
    { yyval.num =  1; }
    break;

  case 719:
#line 2398 "sql_yacc.yy"
    { yyval.num =1; }
    break;

  case 720:
#line 2399 "sql_yacc.yy"
    { yyval.num =0; }
    break;

  case 721:
#line 2403 "sql_yacc.yy"
    {}
    break;

  case 722:
#line 2405 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    if (lex->select->olap != UNSPECIFIED_OLAP_TYPE)
	    {
	      net_printf(&lex->thd->net, ER_WRONG_USAGE, "CUBE/ROLLUP",
		        "LIMIT");
	      YYABORT;
	    }
	  }
    break;

  case 723:
#line 2415 "sql_yacc.yy"
    {}
    break;

  case 724:
#line 2420 "sql_yacc.yy"
    {
            SELECT_LEX *sel= Select;
            sel->select_limit= yyvsp[0].ulong_num;
            sel->offset_limit= 0L;
	  }
    break;

  case 725:
#line 2426 "sql_yacc.yy"
    {
	    SELECT_LEX *sel= Select;
	    sel->select_limit= yyvsp[0].ulong_num;
	    sel->offset_limit= yyvsp[-2].ulong_num;
	  }
    break;

  case 726:
#line 2432 "sql_yacc.yy"
    {
	    SELECT_LEX *sel= Select;
	    sel->select_limit= yyvsp[-2].ulong_num;
	    sel->offset_limit= yyvsp[0].ulong_num;
	  }
    break;

  case 727:
#line 2441 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->select->select_limit= HA_POS_ERROR;
	}
    break;

  case 728:
#line 2446 "sql_yacc.yy"
    { Select->select_limit= (ha_rows) yyvsp[0].ulonglong_number; }
    break;

  case 729:
#line 2449 "sql_yacc.yy"
    { yyval.ulong_num= strtoul(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 730:
#line 2450 "sql_yacc.yy"
    { yyval.ulong_num= (ulong) strtoll(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 731:
#line 2451 "sql_yacc.yy"
    { yyval.ulong_num= (ulong) strtoull(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 732:
#line 2452 "sql_yacc.yy"
    { yyval.ulong_num= strtoul(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 733:
#line 2453 "sql_yacc.yy"
    { yyval.ulong_num= strtoul(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 734:
#line 2456 "sql_yacc.yy"
    { yyval.ulonglong_number= (ulonglong) strtoul(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 735:
#line 2457 "sql_yacc.yy"
    { yyval.ulonglong_number= strtoull(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 736:
#line 2458 "sql_yacc.yy"
    { yyval.ulonglong_number= (ulonglong) strtoll(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 737:
#line 2459 "sql_yacc.yy"
    { yyval.ulonglong_number= strtoull(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 738:
#line 2460 "sql_yacc.yy"
    { yyval.ulonglong_number= strtoull(yyvsp[0].lex_str.str,NULL,10); }
    break;

  case 740:
#line 2465 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->proc_list.elements=0;
	    lex->proc_list.first=0;
	    lex->proc_list.next= (byte**) &lex->proc_list.first;
	    if (add_proc_to_list(lex->thd, new Item_field(NULL,NULL,yyvsp[0].lex_str.str)))
	      YYABORT;
	    current_thd->safe_to_cache_query=0;
	  }
    break;

  case 742:
#line 2478 "sql_yacc.yy"
    {}
    break;

  case 743:
#line 2479 "sql_yacc.yy"
    {}
    break;

  case 746:
#line 2487 "sql_yacc.yy"
    {
	    LEX *lex= Lex;
	    if (add_proc_to_list(lex->thd, yyvsp[0].item))
	      YYABORT;
	    if (!yyvsp[0].item->name)
	      yyvsp[0].item->set_name(yyvsp[-1].simple_string,(uint) ((char*) lex->tok_end - yyvsp[-1].simple_string));
	  }
    break;

  case 747:
#line 2497 "sql_yacc.yy"
    {
	  THD *thd= current_thd;
	  thd->safe_to_cache_query= 0; 
	  if (!(thd->lex.exchange= new sql_exchange(yyvsp[0].lex_str.str,0)))
	    YYABORT;
	}
    break;

  case 749:
#line 2505 "sql_yacc.yy"
    {
	  THD *thd= current_thd;
	  thd->safe_to_cache_query= 0;
	  if (!(thd->lex.exchange= new sql_exchange(yyvsp[0].lex_str.str,1)))
	    YYABORT;
	}
    break;

  case 750:
#line 2517 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command = SQLCOM_DO;
	  if (!(lex->insert_list = new List_item))
	    YYABORT;
	}
    break;

  case 751:
#line 2524 "sql_yacc.yy"
    {}
    break;

  case 752:
#line 2533 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command = SQLCOM_DROP_TABLE;
	  lex->drop_temporary= yyvsp[-4].num;
	  lex->drop_if_exists= yyvsp[-2].num;
	}
    break;

  case 753:
#line 2539 "sql_yacc.yy"
    {}
    break;

  case 754:
#line 2540 "sql_yacc.yy"
    {
	     LEX *lex=Lex;
	     lex->sql_command= SQLCOM_DROP_INDEX;
	     lex->drop_list.empty();
	     lex->drop_list.push_back(new Alter_drop(Alter_drop::KEY,
						     yyvsp[-3].lex_str.str));
	     if (!add_table_to_list(yyvsp[-1].table, NULL, TL_OPTION_UPDATING))
	      YYABORT;
	  }
    break;

  case 755:
#line 2550 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command= SQLCOM_DROP_DB;
	    lex->drop_if_exists=yyvsp[-1].num;
	    lex->name=yyvsp[0].lex_str.str;
	 }
    break;

  case 756:
#line 2557 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command = SQLCOM_DROP_FUNCTION;
	    lex->udf.name=yyvsp[0].lex_str.str;
	  }
    break;

  case 759:
#line 2570 "sql_yacc.yy"
    { if (!add_table_to_list(yyvsp[0].table,NULL,TL_OPTION_UPDATING)) YYABORT; }
    break;

  case 760:
#line 2573 "sql_yacc.yy"
    { yyval.num= 0; }
    break;

  case 761:
#line 2574 "sql_yacc.yy"
    { yyval.num= 1; }
    break;

  case 762:
#line 2578 "sql_yacc.yy"
    { yyval.num= 0; }
    break;

  case 763:
#line 2579 "sql_yacc.yy"
    { yyval.num= 1; }
    break;

  case 764:
#line 2586 "sql_yacc.yy"
    { Lex->sql_command = SQLCOM_INSERT; }
    break;

  case 765:
#line 2588 "sql_yacc.yy"
    {
	  set_lock_for_tables(yyvsp[-2].lock_type);
	  Lex->select= &Lex->select_lex;
	}
    break;

  case 766:
#line 2593 "sql_yacc.yy"
    {}
    break;

  case 767:
#line 2598 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command = SQLCOM_REPLACE;
	  lex->duplicates= DUP_REPLACE;
	}
    break;

  case 768:
#line 2604 "sql_yacc.yy"
    {
	  set_lock_for_tables(yyvsp[-1].lock_type);
          Lex->select= &Lex->select_lex;
	}
    break;

  case 769:
#line 2609 "sql_yacc.yy"
    {}
    break;

  case 770:
#line 2613 "sql_yacc.yy"
    { yyval.lock_type= TL_WRITE_CONCURRENT_INSERT; }
    break;

  case 771:
#line 2614 "sql_yacc.yy"
    { yyval.lock_type= TL_WRITE_LOW_PRIORITY; }
    break;

  case 772:
#line 2615 "sql_yacc.yy"
    { yyval.lock_type= TL_WRITE_DELAYED; }
    break;

  case 773:
#line 2616 "sql_yacc.yy"
    { yyval.lock_type= TL_WRITE; }
    break;

  case 774:
#line 2620 "sql_yacc.yy"
    { yyval.lock_type= yyvsp[0].lock_type; }
    break;

  case 775:
#line 2621 "sql_yacc.yy"
    { yyval.lock_type= TL_WRITE_DELAYED; }
    break;

  case 776:
#line 2624 "sql_yacc.yy"
    {}
    break;

  case 777:
#line 2625 "sql_yacc.yy"
    {}
    break;

  case 778:
#line 2629 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->field_list.empty();
	  lex->many_values.empty();
	  lex->insert_list=0;
	}
    break;

  case 779:
#line 2637 "sql_yacc.yy"
    {}
    break;

  case 780:
#line 2638 "sql_yacc.yy"
    {}
    break;

  case 781:
#line 2639 "sql_yacc.yy"
    {}
    break;

  case 782:
#line 2641 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    if (!(lex->insert_list = new List_item) ||
		lex->many_values.push_back(lex->insert_list))
	      YYABORT;
	   }
    break;

  case 784:
#line 2650 "sql_yacc.yy"
    { }
    break;

  case 785:
#line 2651 "sql_yacc.yy"
    { }
    break;

  case 786:
#line 2652 "sql_yacc.yy"
    { }
    break;

  case 787:
#line 2655 "sql_yacc.yy"
    { Lex->field_list.push_back(yyvsp[0].item); }
    break;

  case 788:
#line 2656 "sql_yacc.yy"
    { Lex->field_list.push_back(yyvsp[0].item); }
    break;

  case 789:
#line 2659 "sql_yacc.yy"
    {}
    break;

  case 790:
#line 2660 "sql_yacc.yy"
    { Select->braces= 0;}
    break;

  case 791:
#line 2660 "sql_yacc.yy"
    {}
    break;

  case 792:
#line 2661 "sql_yacc.yy"
    { Select->braces= 1;}
    break;

  case 793:
#line 2661 "sql_yacc.yy"
    {}
    break;

  case 798:
#line 2675 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  if (lex->field_list.push_back(yyvsp[-2].item) ||
	      lex->insert_list->push_back(yyvsp[0].item))
	    YYABORT;
	 }
    break;

  case 799:
#line 2682 "sql_yacc.yy"
    {}
    break;

  case 800:
#line 2683 "sql_yacc.yy"
    {}
    break;

  case 801:
#line 2687 "sql_yacc.yy"
    {}
    break;

  case 802:
#line 2688 "sql_yacc.yy"
    {}
    break;

  case 803:
#line 2693 "sql_yacc.yy"
    {
	    if (!(Lex->insert_list = new List_item))
	      YYABORT;
	 }
    break;

  case 804:
#line 2698 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  if (lex->many_values.push_back(lex->insert_list))
	    YYABORT;
	 }
    break;

  case 805:
#line 2705 "sql_yacc.yy"
    {}
    break;

  case 807:
#line 2710 "sql_yacc.yy"
    {
	  if (Lex->insert_list->push_back(yyvsp[0].item))
	    YYABORT;
	}
    break;

  case 808:
#line 2715 "sql_yacc.yy"
    {
	    if (Lex->insert_list->push_back(yyvsp[0].item))
	      YYABORT;
	  }
    break;

  case 809:
#line 2722 "sql_yacc.yy"
    { yyval.item= yyvsp[0].item;}
    break;

  case 810:
#line 2723 "sql_yacc.yy"
    {yyval.item= new Item_default(); }
    break;

  case 811:
#line 2730 "sql_yacc.yy"
    { 
	  LEX *lex=Lex;
          lex->sql_command = SQLCOM_UPDATE;
          lex->select->order_list.elements=0;
          lex->select->order_list.first=0;
          lex->select->order_list.next= (byte**) &lex->select->order_list.first;
        }
    break;

  case 812:
#line 2739 "sql_yacc.yy"
    {
	  set_lock_for_tables(yyvsp[-7].lock_type);
	}
    break;

  case 813:
#line 2746 "sql_yacc.yy"
    {
	  if (add_item_to_list(yyvsp[-2].item) || add_value_to_list(yyvsp[0].item))
	    YYABORT;
	}
    break;

  case 814:
#line 2751 "sql_yacc.yy"
    {
	    if (add_item_to_list(yyvsp[-2].item) || add_value_to_list(yyvsp[0].item))
	      YYABORT;
	  }
    break;

  case 815:
#line 2757 "sql_yacc.yy"
    { yyval.lock_type= current_thd->update_lock_default; }
    break;

  case 816:
#line 2758 "sql_yacc.yy"
    { yyval.lock_type= TL_WRITE_LOW_PRIORITY; }
    break;

  case 817:
#line 2764 "sql_yacc.yy"
    { 
	  LEX *lex=Lex;
	  lex->sql_command= SQLCOM_DELETE; lex->select->options=0;
	  lex->lock_option= lex->thd->update_lock_default;
	  lex->select->order_list.elements=0;
	  lex->select->order_list.first=0;
	  lex->select->order_list.next= (byte**) &lex->select->order_list.first;
	}
    break;

  case 818:
#line 2772 "sql_yacc.yy"
    {}
    break;

  case 819:
#line 2777 "sql_yacc.yy"
    {
	  if (!add_table_to_list(yyvsp[0].table, NULL, TL_OPTION_UPDATING,
				 Lex->lock_option))
	    YYABORT;
	}
    break;

  case 820:
#line 2783 "sql_yacc.yy"
    {}
    break;

  case 821:
#line 2785 "sql_yacc.yy"
    { mysql_init_multi_delete(Lex); }
    break;

  case 823:
#line 2788 "sql_yacc.yy"
    { mysql_init_multi_delete(Lex); }
    break;

  case 824:
#line 2790 "sql_yacc.yy"
    {}
    break;

  case 825:
#line 2794 "sql_yacc.yy"
    {}
    break;

  case 826:
#line 2795 "sql_yacc.yy"
    {}
    break;

  case 827:
#line 2799 "sql_yacc.yy"
    {
	   if (!add_table_to_list(new Table_ident(yyvsp[-1].lex_str), NULL,
				  TL_OPTION_UPDATING, Lex->lock_option))
	     YYABORT;
         }
    break;

  case 828:
#line 2805 "sql_yacc.yy"
    {
	     if (!add_table_to_list(new Table_ident(yyvsp[-3].lex_str,yyvsp[-1].lex_str,0), NULL,
				    TL_OPTION_UPDATING,
				    Lex->lock_option))
	      YYABORT;
	   }
    break;

  case 829:
#line 2814 "sql_yacc.yy"
    {}
    break;

  case 830:
#line 2815 "sql_yacc.yy"
    {}
    break;

  case 831:
#line 2819 "sql_yacc.yy"
    {}
    break;

  case 832:
#line 2820 "sql_yacc.yy"
    {}
    break;

  case 833:
#line 2823 "sql_yacc.yy"
    { Select->options|= OPTION_QUICK; }
    break;

  case 834:
#line 2824 "sql_yacc.yy"
    { Lex->lock_option= TL_WRITE_LOW_PRIORITY; }
    break;

  case 835:
#line 2828 "sql_yacc.yy"
    {
	  LEX* lex = Lex;
	  lex->sql_command= SQLCOM_TRUNCATE;
	  lex->select->options=0;
	  lex->select->order_list.elements=0;
          lex->select->order_list.first=0;
          lex->select->order_list.next= (byte**) &lex->select->order_list.first;
	}
    break;

  case 838:
#line 2844 "sql_yacc.yy"
    { Lex->wild=0;}
    break;

  case 839:
#line 2845 "sql_yacc.yy"
    {}
    break;

  case 840:
#line 2850 "sql_yacc.yy"
    { Lex->sql_command= SQLCOM_SHOW_DATABASES; }
    break;

  case 841:
#line 2852 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command= SQLCOM_SHOW_TABLES;
	    lex->select->db= yyvsp[-1].simple_string; lex->select->options=0;
	   }
    break;

  case 842:
#line 2858 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command= SQLCOM_SHOW_TABLES;
	    lex->select->options|= SELECT_DESCRIBE;
	    lex->select->db= yyvsp[-1].simple_string;
	  }
    break;

  case 843:
#line 2865 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command= SQLCOM_SHOW_OPEN_TABLES;
	    lex->select->db= yyvsp[-1].simple_string;
	    lex->select->options=0;
	  }
    break;

  case 844:
#line 2872 "sql_yacc.yy"
    {
	    Lex->sql_command= SQLCOM_SHOW_FIELDS;
	    if (yyvsp[-1].simple_string)
	      yyvsp[-2].table->change_db(yyvsp[-1].simple_string);
	    if (!add_table_to_list(yyvsp[-2].table, NULL, 0))
	      YYABORT;
	  }
    break;

  case 845:
#line 2883 "sql_yacc.yy"
    {
	    Lex->sql_command = SQLCOM_SHOW_NEW_MASTER;
	    Lex->mi.log_file_name = yyvsp[-8].lex_str.str;
	    Lex->mi.pos = yyvsp[-4].ulonglong_number;
	    Lex->mi.server_id = yyvsp[0].ulong_num;
          }
    break;

  case 846:
#line 2890 "sql_yacc.yy"
    {
	    Lex->sql_command = SQLCOM_SHOW_BINLOGS;
          }
    break;

  case 847:
#line 2894 "sql_yacc.yy"
    {
	    Lex->sql_command = SQLCOM_SHOW_SLAVE_HOSTS;
          }
    break;

  case 848:
#line 2898 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command = SQLCOM_SHOW_BINLOG_EVENTS;
	    lex->select->select_limit= lex->thd->variables.select_limit;
	    lex->select->offset_limit= 0L;
          }
    break;

  case 850:
#line 2905 "sql_yacc.yy"
    {
	    Lex->sql_command= SQLCOM_SHOW_KEYS;
	    if (yyvsp[0].simple_string)
	      yyvsp[-1].table->change_db(yyvsp[0].simple_string);
	    if (!add_table_to_list(yyvsp[-1].table, NULL, 0))
	      YYABORT;
	  }
    break;

  case 851:
#line 2913 "sql_yacc.yy"
    { Lex->sql_command= SQLCOM_SHOW_STATUS; }
    break;

  case 852:
#line 2915 "sql_yacc.yy"
    { Lex->sql_command = SQLCOM_SHOW_INNODB_STATUS;}
    break;

  case 853:
#line 2917 "sql_yacc.yy"
    { Lex->sql_command= SQLCOM_SHOW_PROCESSLIST;}
    break;

  case 854:
#line 2919 "sql_yacc.yy"
    {
	    THD *thd= current_thd;
	    thd->lex.sql_command= SQLCOM_SHOW_VARIABLES;
	    thd->lex.option_type= (enum_var_type) yyvsp[-2].num;
	  }
    break;

  case 855:
#line 2925 "sql_yacc.yy"
    { Lex->sql_command= SQLCOM_SHOW_LOGS; }
    break;

  case 856:
#line 2927 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->sql_command= SQLCOM_SHOW_GRANTS;
	    lex->grant_user=yyvsp[0].lex_user;
	    lex->grant_user->password.str=NullS;
	  }
    break;

  case 857:
#line 2934 "sql_yacc.yy"
    {
	    Lex->sql_command = SQLCOM_SHOW_CREATE;
	    if(!add_table_to_list(yyvsp[0].table, NULL, 0))
	      YYABORT;
	  }
    break;

  case 858:
#line 2940 "sql_yacc.yy"
    {
	    Lex->sql_command = SQLCOM_SHOW_MASTER_STAT;
          }
    break;

  case 859:
#line 2944 "sql_yacc.yy"
    {
	    Lex->sql_command = SQLCOM_SHOW_SLAVE_STAT;
          }
    break;

  case 860:
#line 2949 "sql_yacc.yy"
    { yyval.simple_string= 0; }
    break;

  case 861:
#line 2950 "sql_yacc.yy"
    { yyval.simple_string= yyvsp[0].lex_str.str; }
    break;

  case 863:
#line 2954 "sql_yacc.yy"
    { Lex->wild= yyvsp[0].string; }
    break;

  case 864:
#line 2957 "sql_yacc.yy"
    { Lex->verbose=0; }
    break;

  case 865:
#line 2958 "sql_yacc.yy"
    { Lex->verbose=1; }
    break;

  case 868:
#line 2965 "sql_yacc.yy"
    { Lex->mi.log_file_name = 0; }
    break;

  case 869:
#line 2966 "sql_yacc.yy"
    { Lex->mi.log_file_name = yyvsp[0].lex_str.str; }
    break;

  case 870:
#line 2969 "sql_yacc.yy"
    { Lex->mi.pos = 4; /* skip magic number */ }
    break;

  case 871:
#line 2970 "sql_yacc.yy"
    { Lex->mi.pos = yyvsp[0].ulonglong_number; }
    break;

  case 872:
#line 2976 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->wild=0;
	  lex->verbose=0;
	  lex->sql_command=SQLCOM_SHOW_FIELDS;
	  if (!add_table_to_list(yyvsp[0].table, NULL, 0))
	    YYABORT;
	}
    break;

  case 873:
#line 2984 "sql_yacc.yy"
    {}
    break;

  case 874:
#line 2986 "sql_yacc.yy"
    { Lex->select_lex.options|= SELECT_DESCRIBE; }
    break;

  case 877:
#line 2994 "sql_yacc.yy"
    {}
    break;

  case 878:
#line 2995 "sql_yacc.yy"
    { Lex->wild= yyvsp[0].string; }
    break;

  case 879:
#line 2997 "sql_yacc.yy"
    { Lex->wild= new String((const char*) yyvsp[0].lex_str.str,yyvsp[0].lex_str.length); }
    break;

  case 880:
#line 3004 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command= SQLCOM_FLUSH; lex->type=0;
	}
    break;

  case 881:
#line 3009 "sql_yacc.yy"
    {}
    break;

  case 884:
#line 3017 "sql_yacc.yy"
    { Lex->type|= REFRESH_TABLES; }
    break;

  case 885:
#line 3017 "sql_yacc.yy"
    {}
    break;

  case 886:
#line 3018 "sql_yacc.yy"
    { Lex->type|= REFRESH_TABLES | REFRESH_READ_LOCK; }
    break;

  case 887:
#line 3019 "sql_yacc.yy"
    { Lex->type|= REFRESH_QUERY_CACHE_FREE; }
    break;

  case 888:
#line 3020 "sql_yacc.yy"
    { Lex->type|= REFRESH_HOSTS; }
    break;

  case 889:
#line 3021 "sql_yacc.yy"
    { Lex->type|= REFRESH_GRANT; }
    break;

  case 890:
#line 3022 "sql_yacc.yy"
    { Lex->type|= REFRESH_LOG; }
    break;

  case 891:
#line 3023 "sql_yacc.yy"
    { Lex->type|= REFRESH_STATUS; }
    break;

  case 892:
#line 3024 "sql_yacc.yy"
    { Lex->type|= REFRESH_SLAVE; }
    break;

  case 893:
#line 3025 "sql_yacc.yy"
    { Lex->type|= REFRESH_MASTER; }
    break;

  case 894:
#line 3026 "sql_yacc.yy"
    { Lex->type|= REFRESH_DES_KEY_FILE; }
    break;

  case 895:
#line 3027 "sql_yacc.yy"
    { Lex->type|= REFRESH_USER_RESOURCES; }
    break;

  case 896:
#line 3030 "sql_yacc.yy"
    {;}
    break;

  case 897:
#line 3031 "sql_yacc.yy"
    {;}
    break;

  case 898:
#line 3035 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command= SQLCOM_RESET; lex->type=0;
	}
    break;

  case 899:
#line 3039 "sql_yacc.yy"
    {}
    break;

  case 902:
#line 3047 "sql_yacc.yy"
    { Lex->type|= REFRESH_SLAVE; }
    break;

  case 903:
#line 3048 "sql_yacc.yy"
    { Lex->type|= REFRESH_MASTER; }
    break;

  case 904:
#line 3049 "sql_yacc.yy"
    { Lex->type|= REFRESH_QUERY_CACHE;}
    break;

  case 905:
#line 3053 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command = SQLCOM_PURGE;
	  lex->type=0;
	}
    break;

  case 906:
#line 3059 "sql_yacc.yy"
    {
	   Lex->to_log = yyvsp[0].lex_str.str;
         }
    break;

  case 907:
#line 3067 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  if (yyvsp[0].item->fix_fields(lex->thd,0))
	  { 
	    send_error(&lex->thd->net, ER_SET_CONSTANTS_ONLY);
	    YYABORT;
	  }
          lex->sql_command=SQLCOM_KILL;
	  lex->thread_id= (ulong) yyvsp[0].item->val_int();
	}
    break;

  case 908:
#line 3081 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command=SQLCOM_CHANGE_DB; lex->select->db= yyvsp[0].lex_str.str;
	}
    break;

  case 909:
#line 3089 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command= SQLCOM_LOAD;
	  lex->lock_option= yyvsp[-3].lock_type;
	  lex->local_file=  yyvsp[-2].num;
	  if (!(lex->exchange= new sql_exchange(yyvsp[0].lex_str.str,0)))
	    YYABORT;
	  lex->field_list.empty();
	}
    break;

  case 910:
#line 3100 "sql_yacc.yy"
    {
	  if (!add_table_to_list(yyvsp[-4].table, NULL, TL_OPTION_UPDATING))
	    YYABORT;
	}
    break;

  case 911:
#line 3106 "sql_yacc.yy"
    {
	  Lex->sql_command = SQLCOM_LOAD_MASTER_TABLE;
	  if (!add_table_to_list(yyvsp[-2].table, NULL, TL_OPTION_UPDATING))
	    YYABORT;

        }
    break;

  case 912:
#line 3114 "sql_yacc.yy"
    {
	  Lex->sql_command = SQLCOM_LOAD_MASTER_DATA;
        }
    break;

  case 913:
#line 3119 "sql_yacc.yy"
    { yyval.num=0;}
    break;

  case 914:
#line 3120 "sql_yacc.yy"
    { yyval.num=1;}
    break;

  case 915:
#line 3123 "sql_yacc.yy"
    { yyval.lock_type= current_thd->update_lock_default; }
    break;

  case 916:
#line 3124 "sql_yacc.yy"
    { yyval.lock_type= TL_WRITE_CONCURRENT_INSERT ; }
    break;

  case 917:
#line 3125 "sql_yacc.yy"
    { yyval.lock_type= TL_WRITE_LOW_PRIORITY; }
    break;

  case 918:
#line 3129 "sql_yacc.yy"
    { Lex->duplicates=DUP_ERROR; }
    break;

  case 919:
#line 3130 "sql_yacc.yy"
    { Lex->duplicates=DUP_REPLACE; }
    break;

  case 920:
#line 3131 "sql_yacc.yy"
    { Lex->duplicates=DUP_IGNORE; }
    break;

  case 925:
#line 3142 "sql_yacc.yy"
    { Lex->exchange->field_term= yyvsp[0].string;}
    break;

  case 926:
#line 3144 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->exchange->enclosed= yyvsp[0].string;
	    lex->exchange->opt_enclosed=1;
	  }
    break;

  case 927:
#line 3149 "sql_yacc.yy"
    { Lex->exchange->enclosed= yyvsp[0].string;}
    break;

  case 928:
#line 3150 "sql_yacc.yy"
    { Lex->exchange->escaped= yyvsp[0].string;}
    break;

  case 933:
#line 3161 "sql_yacc.yy"
    { Lex->exchange->line_term= yyvsp[0].string;}
    break;

  case 934:
#line 3162 "sql_yacc.yy"
    { Lex->exchange->line_start= yyvsp[0].string;}
    break;

  case 936:
#line 3167 "sql_yacc.yy"
    { Lex->exchange->skip_lines=atol(yyvsp[-1].lex_str.str); }
    break;

  case 937:
#line 3172 "sql_yacc.yy"
    { yyval.item = new Item_string(yyvsp[0].lex_str.str,yyvsp[0].lex_str.length); }
    break;

  case 938:
#line 3174 "sql_yacc.yy"
    { ((Item_string*) yyvsp[-1].item)->append(yyvsp[0].lex_str.str,yyvsp[0].lex_str.length); }
    break;

  case 939:
#line 3177 "sql_yacc.yy"
    { yyval.string=  new String(yyvsp[0].lex_str.str,yyvsp[0].lex_str.length); }
    break;

  case 940:
#line 3179 "sql_yacc.yy"
    {
	    Item *tmp = new Item_varbinary(yyvsp[0].lex_str.str,yyvsp[0].lex_str.length);
	    yyval.string= tmp ? tmp->val_str((String*) 0) : (String*) 0;
	  }
    break;

  case 941:
#line 3185 "sql_yacc.yy"
    { yyval.item =	yyvsp[0].item; }
    break;

  case 942:
#line 3186 "sql_yacc.yy"
    { yyval.item =	new Item_int(yyvsp[0].lex_str.str, (longlong) strtol(yyvsp[0].lex_str.str, NULL, 10),yyvsp[0].lex_str.length); }
    break;

  case 943:
#line 3187 "sql_yacc.yy"
    { yyval.item =	new Item_int(yyvsp[0].lex_str.str, (longlong) strtoll(yyvsp[0].lex_str.str,NULL,10), yyvsp[0].lex_str.length); }
    break;

  case 944:
#line 3188 "sql_yacc.yy"
    { yyval.item =	new Item_uint(yyvsp[0].lex_str.str, yyvsp[0].lex_str.length); }
    break;

  case 945:
#line 3189 "sql_yacc.yy"
    { yyval.item =	new Item_real(yyvsp[0].lex_str.str, yyvsp[0].lex_str.length); }
    break;

  case 946:
#line 3190 "sql_yacc.yy"
    { yyval.item =	new Item_float(yyvsp[0].lex_str.str, yyvsp[0].lex_str.length); }
    break;

  case 947:
#line 3191 "sql_yacc.yy"
    { yyval.item =	new Item_null();
			  Lex->next_state=STATE_OPERATOR_OR_IDENT;}
    break;

  case 948:
#line 3193 "sql_yacc.yy"
    { yyval.item =	new Item_varbinary(yyvsp[0].lex_str.str,yyvsp[0].lex_str.length);}
    break;

  case 949:
#line 3194 "sql_yacc.yy"
    { yyval.item = yyvsp[0].item; }
    break;

  case 950:
#line 3195 "sql_yacc.yy"
    { yyval.item = yyvsp[0].item; }
    break;

  case 951:
#line 3196 "sql_yacc.yy"
    { yyval.item = yyvsp[0].item; }
    break;

  case 952:
#line 3203 "sql_yacc.yy"
    { yyval.item=yyvsp[0].item; }
    break;

  case 953:
#line 3204 "sql_yacc.yy"
    { yyval.item=yyvsp[0].item; }
    break;

  case 954:
#line 3207 "sql_yacc.yy"
    { yyval.item = new Item_field(NullS,yyvsp[-2].lex_str.str,"*"); }
    break;

  case 955:
#line 3209 "sql_yacc.yy"
    { yyval.item = new Item_field((current_thd->client_capabilities &
   CLIENT_NO_SCHEMA ? NullS : yyvsp[-4].lex_str.str),yyvsp[-2].lex_str.str,"*"); }
    break;

  case 956:
#line 3213 "sql_yacc.yy"
    { yyval.item=yyvsp[0].item; }
    break;

  case 957:
#line 3217 "sql_yacc.yy"
    {
	  SELECT_LEX *sel=Select;
	  yyval.item = !sel->create_refs || sel->in_sum_expr > 0 ? (Item*) new Item_field(NullS,NullS,yyvsp[0].lex_str.str) : (Item*) new Item_ref(NullS,NullS,yyvsp[0].lex_str.str);
	}
    break;

  case 958:
#line 3222 "sql_yacc.yy"
    {
	  SELECT_LEX *sel=Select;
	  yyval.item = !sel->create_refs || sel->in_sum_expr > 0 ? (Item*) new Item_field(NullS,yyvsp[-2].lex_str.str,yyvsp[0].lex_str.str) : (Item*) new Item_ref(NullS,yyvsp[-2].lex_str.str,yyvsp[0].lex_str.str);
	}
    break;

  case 959:
#line 3227 "sql_yacc.yy"
    {
	  SELECT_LEX *sel=Select;
	  yyval.item = !sel->create_refs || sel->in_sum_expr > 0 ? (Item*) new Item_field(NullS,yyvsp[-2].lex_str.str,yyvsp[0].lex_str.str) : (Item*) new Item_ref(NullS,yyvsp[-2].lex_str.str,yyvsp[0].lex_str.str);
	}
    break;

  case 960:
#line 3232 "sql_yacc.yy"
    {
	  SELECT_LEX *sel=Select;
	  yyval.item = !sel->create_refs || sel->in_sum_expr > 0 ? (Item*) new Item_field((current_thd->client_capabilities & CLIENT_NO_SCHEMA ? NullS :yyvsp[-4].lex_str.str),yyvsp[-2].lex_str.str,yyvsp[0].lex_str.str) : (Item*) new Item_ref((current_thd->client_capabilities & CLIENT_NO_SCHEMA ? NullS :yyvsp[-4].lex_str.str),yyvsp[-2].lex_str.str,yyvsp[0].lex_str.str);
	}
    break;

  case 961:
#line 3239 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str;}
    break;

  case 962:
#line 3240 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str;}
    break;

  case 963:
#line 3241 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str;}
    break;

  case 964:
#line 3244 "sql_yacc.yy"
    { yyval.table=new Table_ident(yyvsp[0].lex_str); }
    break;

  case 965:
#line 3245 "sql_yacc.yy"
    { yyval.table=new Table_ident(yyvsp[-2].lex_str,yyvsp[0].lex_str,0);}
    break;

  case 966:
#line 3246 "sql_yacc.yy"
    { yyval.table=new Table_ident(yyvsp[0].lex_str);}
    break;

  case 967:
#line 3250 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str; }
    break;

  case 968:
#line 3252 "sql_yacc.yy"
    {
	  LEX *lex= Lex;
	  yyval.lex_str.str= lex->thd->strmake(yyvsp[0].symbol.str,yyvsp[0].symbol.length);
	  yyval.lex_str.length=yyvsp[0].symbol.length;
	  if (lex->next_state != STATE_END)
	    lex->next_state=STATE_OPERATOR_OR_IDENT;
	}
    break;

  case 969:
#line 3262 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str;}
    break;

  case 970:
#line 3263 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str;}
    break;

  case 971:
#line 3264 "sql_yacc.yy"
    { yyval.lex_str=yyvsp[0].lex_str;}
    break;

  case 972:
#line 3268 "sql_yacc.yy"
    {
	  if (!(yyval.lex_user=(LEX_USER*) sql_alloc(sizeof(st_lex_user))))
	    YYABORT;
	  yyval.lex_user->user = yyvsp[0].lex_str; yyval.lex_user->host.str=NullS;
	  }
    break;

  case 973:
#line 3274 "sql_yacc.yy"
    {
	  if (!(yyval.lex_user=(LEX_USER*) sql_alloc(sizeof(st_lex_user))))
	      YYABORT;
	    yyval.lex_user->user = yyvsp[-2].lex_str; yyval.lex_user->host=yyvsp[0].lex_str;
	  }
    break;

  case 974:
#line 3283 "sql_yacc.yy"
    {}
    break;

  case 975:
#line 3284 "sql_yacc.yy"
    {}
    break;

  case 976:
#line 3285 "sql_yacc.yy"
    {}
    break;

  case 977:
#line 3286 "sql_yacc.yy"
    {}
    break;

  case 978:
#line 3287 "sql_yacc.yy"
    {}
    break;

  case 979:
#line 3288 "sql_yacc.yy"
    {}
    break;

  case 980:
#line 3289 "sql_yacc.yy"
    {}
    break;

  case 981:
#line 3290 "sql_yacc.yy"
    {}
    break;

  case 982:
#line 3291 "sql_yacc.yy"
    {}
    break;

  case 983:
#line 3292 "sql_yacc.yy"
    {}
    break;

  case 984:
#line 3293 "sql_yacc.yy"
    {}
    break;

  case 985:
#line 3294 "sql_yacc.yy"
    {}
    break;

  case 986:
#line 3295 "sql_yacc.yy"
    {}
    break;

  case 987:
#line 3296 "sql_yacc.yy"
    {}
    break;

  case 988:
#line 3297 "sql_yacc.yy"
    {}
    break;

  case 989:
#line 3298 "sql_yacc.yy"
    {}
    break;

  case 990:
#line 3299 "sql_yacc.yy"
    {}
    break;

  case 991:
#line 3300 "sql_yacc.yy"
    {}
    break;

  case 992:
#line 3301 "sql_yacc.yy"
    {}
    break;

  case 993:
#line 3302 "sql_yacc.yy"
    {}
    break;

  case 994:
#line 3303 "sql_yacc.yy"
    {}
    break;

  case 995:
#line 3304 "sql_yacc.yy"
    {}
    break;

  case 996:
#line 3305 "sql_yacc.yy"
    {}
    break;

  case 997:
#line 3306 "sql_yacc.yy"
    {}
    break;

  case 998:
#line 3307 "sql_yacc.yy"
    {}
    break;

  case 999:
#line 3308 "sql_yacc.yy"
    {}
    break;

  case 1000:
#line 3309 "sql_yacc.yy"
    {}
    break;

  case 1001:
#line 3310 "sql_yacc.yy"
    {}
    break;

  case 1002:
#line 3311 "sql_yacc.yy"
    {}
    break;

  case 1003:
#line 3312 "sql_yacc.yy"
    {}
    break;

  case 1004:
#line 3313 "sql_yacc.yy"
    {}
    break;

  case 1005:
#line 3314 "sql_yacc.yy"
    {}
    break;

  case 1006:
#line 3315 "sql_yacc.yy"
    {}
    break;

  case 1007:
#line 3316 "sql_yacc.yy"
    {}
    break;

  case 1008:
#line 3317 "sql_yacc.yy"
    {}
    break;

  case 1009:
#line 3318 "sql_yacc.yy"
    {}
    break;

  case 1010:
#line 3319 "sql_yacc.yy"
    {}
    break;

  case 1011:
#line 3320 "sql_yacc.yy"
    {}
    break;

  case 1012:
#line 3321 "sql_yacc.yy"
    {}
    break;

  case 1013:
#line 3322 "sql_yacc.yy"
    {}
    break;

  case 1014:
#line 3323 "sql_yacc.yy"
    {}
    break;

  case 1015:
#line 3324 "sql_yacc.yy"
    {}
    break;

  case 1016:
#line 3325 "sql_yacc.yy"
    {}
    break;

  case 1017:
#line 3326 "sql_yacc.yy"
    {}
    break;

  case 1018:
#line 3327 "sql_yacc.yy"
    {}
    break;

  case 1019:
#line 3328 "sql_yacc.yy"
    {}
    break;

  case 1020:
#line 3329 "sql_yacc.yy"
    {}
    break;

  case 1021:
#line 3330 "sql_yacc.yy"
    {}
    break;

  case 1022:
#line 3331 "sql_yacc.yy"
    {}
    break;

  case 1023:
#line 3332 "sql_yacc.yy"
    {}
    break;

  case 1024:
#line 3333 "sql_yacc.yy"
    {}
    break;

  case 1025:
#line 3334 "sql_yacc.yy"
    {}
    break;

  case 1026:
#line 3335 "sql_yacc.yy"
    {}
    break;

  case 1027:
#line 3336 "sql_yacc.yy"
    {}
    break;

  case 1028:
#line 3337 "sql_yacc.yy"
    {}
    break;

  case 1029:
#line 3338 "sql_yacc.yy"
    {}
    break;

  case 1030:
#line 3339 "sql_yacc.yy"
    {}
    break;

  case 1031:
#line 3340 "sql_yacc.yy"
    {}
    break;

  case 1032:
#line 3341 "sql_yacc.yy"
    {}
    break;

  case 1033:
#line 3342 "sql_yacc.yy"
    {}
    break;

  case 1034:
#line 3343 "sql_yacc.yy"
    {}
    break;

  case 1035:
#line 3344 "sql_yacc.yy"
    {}
    break;

  case 1036:
#line 3345 "sql_yacc.yy"
    {}
    break;

  case 1037:
#line 3346 "sql_yacc.yy"
    {}
    break;

  case 1038:
#line 3347 "sql_yacc.yy"
    {}
    break;

  case 1039:
#line 3348 "sql_yacc.yy"
    {}
    break;

  case 1040:
#line 3349 "sql_yacc.yy"
    {}
    break;

  case 1041:
#line 3350 "sql_yacc.yy"
    {}
    break;

  case 1042:
#line 3351 "sql_yacc.yy"
    {}
    break;

  case 1043:
#line 3352 "sql_yacc.yy"
    {}
    break;

  case 1044:
#line 3353 "sql_yacc.yy"
    {}
    break;

  case 1045:
#line 3354 "sql_yacc.yy"
    {}
    break;

  case 1046:
#line 3355 "sql_yacc.yy"
    {}
    break;

  case 1047:
#line 3356 "sql_yacc.yy"
    {}
    break;

  case 1048:
#line 3357 "sql_yacc.yy"
    {}
    break;

  case 1049:
#line 3358 "sql_yacc.yy"
    {}
    break;

  case 1050:
#line 3359 "sql_yacc.yy"
    {}
    break;

  case 1051:
#line 3360 "sql_yacc.yy"
    {}
    break;

  case 1052:
#line 3361 "sql_yacc.yy"
    {}
    break;

  case 1053:
#line 3362 "sql_yacc.yy"
    {}
    break;

  case 1054:
#line 3363 "sql_yacc.yy"
    {}
    break;

  case 1055:
#line 3364 "sql_yacc.yy"
    {}
    break;

  case 1056:
#line 3365 "sql_yacc.yy"
    {}
    break;

  case 1057:
#line 3366 "sql_yacc.yy"
    {}
    break;

  case 1058:
#line 3367 "sql_yacc.yy"
    {}
    break;

  case 1059:
#line 3368 "sql_yacc.yy"
    {}
    break;

  case 1060:
#line 3369 "sql_yacc.yy"
    {}
    break;

  case 1061:
#line 3370 "sql_yacc.yy"
    {}
    break;

  case 1062:
#line 3371 "sql_yacc.yy"
    {}
    break;

  case 1063:
#line 3372 "sql_yacc.yy"
    {}
    break;

  case 1064:
#line 3373 "sql_yacc.yy"
    {}
    break;

  case 1065:
#line 3374 "sql_yacc.yy"
    {}
    break;

  case 1066:
#line 3375 "sql_yacc.yy"
    {}
    break;

  case 1067:
#line 3376 "sql_yacc.yy"
    {}
    break;

  case 1068:
#line 3377 "sql_yacc.yy"
    {}
    break;

  case 1069:
#line 3378 "sql_yacc.yy"
    {}
    break;

  case 1070:
#line 3379 "sql_yacc.yy"
    {}
    break;

  case 1071:
#line 3380 "sql_yacc.yy"
    {}
    break;

  case 1072:
#line 3381 "sql_yacc.yy"
    {}
    break;

  case 1073:
#line 3382 "sql_yacc.yy"
    {}
    break;

  case 1074:
#line 3383 "sql_yacc.yy"
    {}
    break;

  case 1075:
#line 3384 "sql_yacc.yy"
    {}
    break;

  case 1076:
#line 3385 "sql_yacc.yy"
    {}
    break;

  case 1077:
#line 3386 "sql_yacc.yy"
    {}
    break;

  case 1078:
#line 3387 "sql_yacc.yy"
    {}
    break;

  case 1079:
#line 3388 "sql_yacc.yy"
    {}
    break;

  case 1080:
#line 3389 "sql_yacc.yy"
    {}
    break;

  case 1081:
#line 3390 "sql_yacc.yy"
    {}
    break;

  case 1082:
#line 3391 "sql_yacc.yy"
    {}
    break;

  case 1083:
#line 3392 "sql_yacc.yy"
    {}
    break;

  case 1084:
#line 3393 "sql_yacc.yy"
    {}
    break;

  case 1085:
#line 3394 "sql_yacc.yy"
    {}
    break;

  case 1086:
#line 3395 "sql_yacc.yy"
    {}
    break;

  case 1087:
#line 3396 "sql_yacc.yy"
    {}
    break;

  case 1088:
#line 3397 "sql_yacc.yy"
    {}
    break;

  case 1089:
#line 3398 "sql_yacc.yy"
    {}
    break;

  case 1090:
#line 3399 "sql_yacc.yy"
    {}
    break;

  case 1091:
#line 3400 "sql_yacc.yy"
    {}
    break;

  case 1092:
#line 3401 "sql_yacc.yy"
    {}
    break;

  case 1093:
#line 3402 "sql_yacc.yy"
    {}
    break;

  case 1094:
#line 3403 "sql_yacc.yy"
    {}
    break;

  case 1095:
#line 3404 "sql_yacc.yy"
    {}
    break;

  case 1096:
#line 3405 "sql_yacc.yy"
    {}
    break;

  case 1097:
#line 3406 "sql_yacc.yy"
    {}
    break;

  case 1098:
#line 3407 "sql_yacc.yy"
    {}
    break;

  case 1099:
#line 3408 "sql_yacc.yy"
    {}
    break;

  case 1100:
#line 3409 "sql_yacc.yy"
    {}
    break;

  case 1101:
#line 3410 "sql_yacc.yy"
    {}
    break;

  case 1102:
#line 3411 "sql_yacc.yy"
    {}
    break;

  case 1103:
#line 3412 "sql_yacc.yy"
    {}
    break;

  case 1104:
#line 3413 "sql_yacc.yy"
    {}
    break;

  case 1105:
#line 3414 "sql_yacc.yy"
    {}
    break;

  case 1106:
#line 3415 "sql_yacc.yy"
    {}
    break;

  case 1107:
#line 3416 "sql_yacc.yy"
    {}
    break;

  case 1108:
#line 3417 "sql_yacc.yy"
    {}
    break;

  case 1109:
#line 3418 "sql_yacc.yy"
    {}
    break;

  case 1110:
#line 3419 "sql_yacc.yy"
    {}
    break;

  case 1111:
#line 3420 "sql_yacc.yy"
    {}
    break;

  case 1112:
#line 3421 "sql_yacc.yy"
    {}
    break;

  case 1113:
#line 3422 "sql_yacc.yy"
    {}
    break;

  case 1114:
#line 3423 "sql_yacc.yy"
    {}
    break;

  case 1115:
#line 3424 "sql_yacc.yy"
    {}
    break;

  case 1116:
#line 3425 "sql_yacc.yy"
    {}
    break;

  case 1117:
#line 3426 "sql_yacc.yy"
    {}
    break;

  case 1118:
#line 3427 "sql_yacc.yy"
    {}
    break;

  case 1119:
#line 3428 "sql_yacc.yy"
    {}
    break;

  case 1120:
#line 3429 "sql_yacc.yy"
    {}
    break;

  case 1121:
#line 3430 "sql_yacc.yy"
    {}
    break;

  case 1122:
#line 3431 "sql_yacc.yy"
    {}
    break;

  case 1123:
#line 3432 "sql_yacc.yy"
    {}
    break;

  case 1124:
#line 3433 "sql_yacc.yy"
    {}
    break;

  case 1125:
#line 3434 "sql_yacc.yy"
    {}
    break;

  case 1126:
#line 3435 "sql_yacc.yy"
    {}
    break;

  case 1127:
#line 3436 "sql_yacc.yy"
    {}
    break;

  case 1128:
#line 3437 "sql_yacc.yy"
    {}
    break;

  case 1129:
#line 3438 "sql_yacc.yy"
    {}
    break;

  case 1130:
#line 3439 "sql_yacc.yy"
    {}
    break;

  case 1131:
#line 3445 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command= SQLCOM_SET_OPTION;
	  lex->option_type=OPT_DEFAULT;
	  lex->var_list.empty();
	}
    break;

  case 1132:
#line 3452 "sql_yacc.yy"
    {}
    break;

  case 1133:
#line 3456 "sql_yacc.yy"
    {}
    break;

  case 1134:
#line 3457 "sql_yacc.yy"
    {}
    break;

  case 1137:
#line 3464 "sql_yacc.yy"
    {}
    break;

  case 1138:
#line 3465 "sql_yacc.yy"
    { Lex->option_type= OPT_GLOBAL; }
    break;

  case 1139:
#line 3466 "sql_yacc.yy"
    { Lex->option_type= OPT_SESSION; }
    break;

  case 1140:
#line 3467 "sql_yacc.yy"
    { Lex->option_type= OPT_SESSION; }
    break;

  case 1141:
#line 3471 "sql_yacc.yy"
    { yyval.num=OPT_SESSION; }
    break;

  case 1142:
#line 3472 "sql_yacc.yy"
    { yyval.num=OPT_SESSION; }
    break;

  case 1143:
#line 3473 "sql_yacc.yy"
    { yyval.num=OPT_SESSION; }
    break;

  case 1144:
#line 3474 "sql_yacc.yy"
    { yyval.num=OPT_GLOBAL; }
    break;

  case 1145:
#line 3478 "sql_yacc.yy"
    { yyval.num=OPT_DEFAULT; }
    break;

  case 1146:
#line 3479 "sql_yacc.yy"
    { yyval.num=OPT_SESSION; }
    break;

  case 1147:
#line 3480 "sql_yacc.yy"
    { yyval.num=OPT_SESSION; }
    break;

  case 1148:
#line 3481 "sql_yacc.yy"
    { yyval.num=OPT_GLOBAL; }
    break;

  case 1149:
#line 3486 "sql_yacc.yy"
    {
	  Lex->var_list.push_back(new set_var_user(new Item_func_set_user_var(yyvsp[-2].lex_str,yyvsp[0].item)));
	}
    break;

  case 1150:
#line 3490 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->var_list.push_back(new set_var(lex->option_type, yyvsp[-2].variable, yyvsp[0].item));
	  }
    break;

  case 1151:
#line 3495 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->var_list.push_back(new set_var((enum_var_type) yyvsp[-3].num, yyvsp[-2].variable, yyvsp[0].item));
	  }
    break;

  case 1152:
#line 3500 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->var_list.push_back(new set_var(lex->option_type,
						find_sys_var("tx_isolation"),
						new Item_int((int32) yyvsp[0].tx_isolation)));
	  }
    break;

  case 1153:
#line 3507 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->var_list.push_back(new set_var(lex->option_type,
					      find_sys_var("convert_character_set"),
					      yyvsp[0].item));
	}
    break;

  case 1154:
#line 3514 "sql_yacc.yy"
    {
	    THD *thd=current_thd;
	    LEX_USER *user;
	    if (!(user=(LEX_USER*) sql_alloc(sizeof(LEX_USER))))
	      YYABORT;
	    user->host.str=0;
	    user->user.str=thd->priv_user;
	    thd->lex.var_list.push_back(new set_var_password(user, yyvsp[0].simple_string));
	  }
    break;

  case 1155:
#line 3524 "sql_yacc.yy"
    {
	    Lex->var_list.push_back(new set_var_password(yyvsp[-2].lex_user,yyvsp[0].simple_string));
	  }
    break;

  case 1156:
#line 3531 "sql_yacc.yy"
    {
	  sys_var *tmp=find_sys_var(yyvsp[0].lex_str.str, yyvsp[0].lex_str.length);
	  if (!tmp)
	    YYABORT;
	  yyval.variable=tmp;
	}
    break;

  case 1157:
#line 3540 "sql_yacc.yy"
    { yyval.tx_isolation= ISO_READ_UNCOMMITTED; }
    break;

  case 1158:
#line 3541 "sql_yacc.yy"
    { yyval.tx_isolation= ISO_READ_COMMITTED; }
    break;

  case 1159:
#line 3542 "sql_yacc.yy"
    { yyval.tx_isolation= ISO_REPEATABLE_READ; }
    break;

  case 1160:
#line 3543 "sql_yacc.yy"
    { yyval.tx_isolation= ISO_SERIALIZABLE; }
    break;

  case 1161:
#line 3547 "sql_yacc.yy"
    { yyval.simple_string=yyvsp[0].lex_str.str;}
    break;

  case 1162:
#line 3549 "sql_yacc.yy"
    {
	    if (!yyvsp[-1].lex_str.length)
	      yyval.simple_string=yyvsp[-1].lex_str.str;
	    else
	    {
	      char *buff=(char*) sql_alloc(HASH_PASSWORD_LENGTH+1);
	      make_scrambled_password(buff,yyvsp[-1].lex_str.str);
	      yyval.simple_string=buff;
	    }
	  }
    break;

  case 1163:
#line 3562 "sql_yacc.yy"
    { yyval.item=yyvsp[0].item; }
    break;

  case 1164:
#line 3563 "sql_yacc.yy"
    { yyval.item=0; }
    break;

  case 1165:
#line 3564 "sql_yacc.yy"
    { yyval.item=new Item_string("ON",2); }
    break;

  case 1166:
#line 3565 "sql_yacc.yy"
    { yyval.item=new Item_string("ALL",3); }
    break;

  case 1167:
#line 3573 "sql_yacc.yy"
    {
	  Lex->sql_command=SQLCOM_LOCK_TABLES;
	}
    break;

  case 1168:
#line 3577 "sql_yacc.yy"
    {}
    break;

  case 1173:
#line 3590 "sql_yacc.yy"
    { if (!add_table_to_list(yyvsp[-2].table,yyvsp[-1].lex_str_ptr,0,(thr_lock_type) yyvsp[0].num)) YYABORT; }
    break;

  case 1174:
#line 3593 "sql_yacc.yy"
    { yyval.num=TL_READ_NO_INSERT; }
    break;

  case 1175:
#line 3594 "sql_yacc.yy"
    { yyval.num=current_thd->update_lock_default; }
    break;

  case 1176:
#line 3595 "sql_yacc.yy"
    { yyval.num=TL_WRITE_LOW_PRIORITY; }
    break;

  case 1177:
#line 3596 "sql_yacc.yy"
    { yyval.num= TL_READ; }
    break;

  case 1178:
#line 3599 "sql_yacc.yy"
    { Lex->sql_command=SQLCOM_UNLOCK_TABLES; }
    break;

  case 1179:
#line 3608 "sql_yacc.yy"
    {
	  Lex->sql_command = SQLCOM_HA_OPEN;
	  if (!add_table_to_list(yyvsp[-2].table,yyvsp[0].lex_str_ptr,0))
	    YYABORT;
	}
    break;

  case 1180:
#line 3614 "sql_yacc.yy"
    {
	  Lex->sql_command = SQLCOM_HA_CLOSE;
	  if (!add_table_to_list(yyvsp[-1].table,0,0))
	    YYABORT;
	}
    break;

  case 1181:
#line 3620 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command = SQLCOM_HA_READ;
	  lex->ha_rkey_mode= HA_READ_KEY_EXACT;	/* Avoid purify warnings */
	  lex->select->select_limit= 1;
	  lex->select->offset_limit= 0L;
	  if (!add_table_to_list(yyvsp[-1].table,0,0))
	    YYABORT;
        }
    break;

  case 1182:
#line 3629 "sql_yacc.yy"
    { }
    break;

  case 1183:
#line 3632 "sql_yacc.yy"
    { Lex->backup_dir= 0; }
    break;

  case 1184:
#line 3633 "sql_yacc.yy"
    { Lex->backup_dir= yyvsp[-1].lex_str.str; }
    break;

  case 1185:
#line 3636 "sql_yacc.yy"
    { Lex->ha_read_mode = RFIRST; }
    break;

  case 1186:
#line 3637 "sql_yacc.yy"
    { Lex->ha_read_mode = RNEXT;  }
    break;

  case 1187:
#line 3640 "sql_yacc.yy"
    { Lex->ha_read_mode = RFIRST; }
    break;

  case 1188:
#line 3641 "sql_yacc.yy"
    { Lex->ha_read_mode = RNEXT;  }
    break;

  case 1189:
#line 3642 "sql_yacc.yy"
    { Lex->ha_read_mode = RPREV;  }
    break;

  case 1190:
#line 3643 "sql_yacc.yy"
    { Lex->ha_read_mode = RLAST;  }
    break;

  case 1191:
#line 3645 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->ha_read_mode = RKEY;
	  lex->ha_rkey_mode=yyvsp[0].ha_rkey_mode;
	  if (!(lex->insert_list = new List_item))
	    YYABORT;
	}
    break;

  case 1192:
#line 3651 "sql_yacc.yy"
    { }
    break;

  case 1193:
#line 3654 "sql_yacc.yy"
    { yyval.ha_rkey_mode=HA_READ_KEY_EXACT;   }
    break;

  case 1194:
#line 3655 "sql_yacc.yy"
    { yyval.ha_rkey_mode=HA_READ_KEY_OR_NEXT; }
    break;

  case 1195:
#line 3656 "sql_yacc.yy"
    { yyval.ha_rkey_mode=HA_READ_KEY_OR_PREV; }
    break;

  case 1196:
#line 3657 "sql_yacc.yy"
    { yyval.ha_rkey_mode=HA_READ_AFTER_KEY;   }
    break;

  case 1197:
#line 3658 "sql_yacc.yy"
    { yyval.ha_rkey_mode=HA_READ_BEFORE_KEY;  }
    break;

  case 1198:
#line 3664 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->sql_command = SQLCOM_REVOKE;
	  lex->users_list.empty();
	  lex->columns.empty();
	  lex->grant= lex->grant_tot_col=0;
	  lex->select->db=0;
	  lex->ssl_type= SSL_TYPE_NOT_SPECIFIED;
	  lex->ssl_cipher= lex->x509_subject= lex->x509_issuer= 0;
	  bzero((char*) &lex->mqh, sizeof(lex->mqh));
	}
    break;

  case 1199:
#line 3676 "sql_yacc.yy"
    {}
    break;

  case 1200:
#line 3681 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->users_list.empty();
	  lex->columns.empty();
	  lex->sql_command = SQLCOM_GRANT;
	  lex->grant= lex->grant_tot_col= 0;
	  lex->select->db= 0;
	  lex->ssl_type= SSL_TYPE_NOT_SPECIFIED;
	  lex->ssl_cipher= lex->x509_subject= lex->x509_issuer= 0;
	  bzero((char *)&(lex->mqh),sizeof(lex->mqh));
	}
    break;

  case 1201:
#line 3694 "sql_yacc.yy"
    {}
    break;

  case 1202:
#line 3698 "sql_yacc.yy"
    {}
    break;

  case 1203:
#line 3699 "sql_yacc.yy"
    { Lex->grant = GLOBAL_ACLS;}
    break;

  case 1204:
#line 3700 "sql_yacc.yy"
    { Lex->grant = GLOBAL_ACLS;}
    break;

  case 1207:
#line 3707 "sql_yacc.yy"
    { Lex->which_columns = SELECT_ACL;}
    break;

  case 1208:
#line 3707 "sql_yacc.yy"
    {}
    break;

  case 1209:
#line 3708 "sql_yacc.yy"
    { Lex->which_columns = INSERT_ACL;}
    break;

  case 1210:
#line 3708 "sql_yacc.yy"
    {}
    break;

  case 1211:
#line 3709 "sql_yacc.yy"
    { Lex->which_columns = UPDATE_ACL; }
    break;

  case 1212:
#line 3709 "sql_yacc.yy"
    {}
    break;

  case 1213:
#line 3710 "sql_yacc.yy"
    { Lex->which_columns = REFERENCES_ACL;}
    break;

  case 1214:
#line 3710 "sql_yacc.yy"
    {}
    break;

  case 1215:
#line 3711 "sql_yacc.yy"
    { Lex->grant |= DELETE_ACL;}
    break;

  case 1216:
#line 3712 "sql_yacc.yy"
    {}
    break;

  case 1217:
#line 3713 "sql_yacc.yy"
    { Lex->grant |= INDEX_ACL;}
    break;

  case 1218:
#line 3714 "sql_yacc.yy"
    { Lex->grant |= ALTER_ACL;}
    break;

  case 1219:
#line 3715 "sql_yacc.yy"
    { Lex->grant |= CREATE_ACL;}
    break;

  case 1220:
#line 3716 "sql_yacc.yy"
    { Lex->grant |= DROP_ACL;}
    break;

  case 1221:
#line 3717 "sql_yacc.yy"
    { Lex->grant |= EXECUTE_ACL;}
    break;

  case 1222:
#line 3718 "sql_yacc.yy"
    { Lex->grant |= RELOAD_ACL;}
    break;

  case 1223:
#line 3719 "sql_yacc.yy"
    { Lex->grant |= SHUTDOWN_ACL;}
    break;

  case 1224:
#line 3720 "sql_yacc.yy"
    { Lex->grant |= PROCESS_ACL;}
    break;

  case 1225:
#line 3721 "sql_yacc.yy"
    { Lex->grant |= FILE_ACL;}
    break;

  case 1226:
#line 3722 "sql_yacc.yy"
    { Lex->grant |= GRANT_ACL;}
    break;

  case 1227:
#line 3723 "sql_yacc.yy"
    { Lex->grant |= SHOW_DB_ACL;}
    break;

  case 1228:
#line 3724 "sql_yacc.yy"
    { Lex->grant |= SUPER_ACL;}
    break;

  case 1229:
#line 3725 "sql_yacc.yy"
    { Lex->grant |= CREATE_TMP_ACL;}
    break;

  case 1230:
#line 3726 "sql_yacc.yy"
    { Lex->grant |= LOCK_TABLES_ACL; }
    break;

  case 1231:
#line 3727 "sql_yacc.yy"
    { Lex->grant |= REPL_SLAVE_ACL;}
    break;

  case 1232:
#line 3728 "sql_yacc.yy"
    { Lex->grant |= REPL_CLIENT_ACL;}
    break;

  case 1233:
#line 3733 "sql_yacc.yy"
    {}
    break;

  case 1234:
#line 3734 "sql_yacc.yy"
    {}
    break;

  case 1237:
#line 3744 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  if (lex->x509_subject)
	  {
	    net_printf(&lex->thd->net,ER_DUP_ARGUMENT, "SUBJECT");
	    YYABORT;
	  }
	  lex->x509_subject=yyvsp[0].lex_str.str;
	}
    break;

  case 1238:
#line 3754 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  if (lex->x509_issuer)
	  {
	    net_printf(&lex->thd->net,ER_DUP_ARGUMENT, "ISSUER");
	    YYABORT;
	  }
	  lex->x509_issuer=yyvsp[0].lex_str.str;
	}
    break;

  case 1239:
#line 3764 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  if (lex->ssl_cipher)
	  {
	    net_printf(&lex->thd->net,ER_DUP_ARGUMENT, "CIPHER");
	    YYABORT;
	  }
	  lex->ssl_cipher=yyvsp[0].lex_str.str;
	}
    break;

  case 1240:
#line 3777 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->select->db=lex->thd->db;
	    if (lex->grant == GLOBAL_ACLS)
	      lex->grant = DB_ACLS & ~GRANT_ACL;
	    else if (lex->columns.elements)
	    {
	      send_error(&lex->thd->net,ER_ILLEGAL_GRANT_FOR_TABLE);
	      YYABORT;
	    }
	  }
    break;

  case 1241:
#line 3789 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->select->db = yyvsp[-2].lex_str.str;
	    if (lex->grant == GLOBAL_ACLS)
	      lex->grant = DB_ACLS & ~GRANT_ACL;
	    else if (lex->columns.elements)
	    {
	      send_error(&lex->thd->net,ER_ILLEGAL_GRANT_FOR_TABLE);
	      YYABORT;
	    }
	  }
    break;

  case 1242:
#line 3801 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    lex->select->db = NULL;
	    if (lex->grant == GLOBAL_ACLS)
	      lex->grant= GLOBAL_ACLS & ~GRANT_ACL;
	    else if (lex->columns.elements)
	    {
	      send_error(&lex->thd->net,ER_ILLEGAL_GRANT_FOR_TABLE);
	      YYABORT;
	    }
	  }
    break;

  case 1243:
#line 3813 "sql_yacc.yy"
    {
	    LEX *lex=Lex;
	    if (!add_table_to_list(yyvsp[0].table,NULL,0))
	      YYABORT;
	    if (lex->grant == GLOBAL_ACLS)
	      lex->grant =  TABLE_ACLS & ~GRANT_ACL;
	  }
    break;

  case 1244:
#line 3823 "sql_yacc.yy"
    { if (Lex->users_list.push_back(yyvsp[0].lex_user)) YYABORT;}
    break;

  case 1245:
#line 3825 "sql_yacc.yy"
    {
	    if (Lex->users_list.push_back(yyvsp[0].lex_user))
	      YYABORT;
	  }
    break;

  case 1246:
#line 3834 "sql_yacc.yy"
    {
	   yyval.lex_user=yyvsp[-3].lex_user; yyvsp[-3].lex_user->password=yyvsp[0].lex_str;
	   if (yyvsp[0].lex_str.length)
	   {
	     char *buff=(char*) sql_alloc(HASH_PASSWORD_LENGTH+1);
	     if (buff)
	     {
	       make_scrambled_password(buff,yyvsp[0].lex_str.str);
	       yyvsp[-3].lex_user->password.str=buff;
	       yyvsp[-3].lex_user->password.length=HASH_PASSWORD_LENGTH;
	     }
	  }
	}
    break;

  case 1247:
#line 3848 "sql_yacc.yy"
    { yyval.lex_user=yyvsp[-4].lex_user; yyvsp[-4].lex_user->password=yyvsp[0].lex_str ; }
    break;

  case 1248:
#line 3850 "sql_yacc.yy"
    { yyval.lex_user=yyvsp[0].lex_user; yyvsp[0].lex_user->password.str=NullS; }
    break;

  case 1249:
#line 3855 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  lex->grant |= lex->which_columns;
	}
    break;

  case 1253:
#line 3867 "sql_yacc.yy"
    {
	  String *new_str = new String((const char*) yyvsp[0].lex_str.str,yyvsp[0].lex_str.length);
	  List_iterator <LEX_COLUMN> iter(Lex->columns);
	  class LEX_COLUMN *point;
	  LEX *lex=Lex;
	  while ((point=iter++))
	  {
	    if (!my_strcasecmp(point->column.ptr(),new_str->ptr()))
		break;
	  }
	  lex->grant_tot_col|= lex->which_columns;
	  if (point)
	    point->rights |= lex->which_columns;
	  else
	    lex->columns.push_back(new LEX_COLUMN (*new_str,lex->which_columns));
	}
    break;

  case 1255:
#line 3887 "sql_yacc.yy"
    {
            Lex->ssl_type=SSL_TYPE_SPECIFIED;
          }
    break;

  case 1256:
#line 3891 "sql_yacc.yy"
    {
            Lex->ssl_type=SSL_TYPE_ANY;
          }
    break;

  case 1257:
#line 3895 "sql_yacc.yy"
    {
            Lex->ssl_type=SSL_TYPE_X509;
          }
    break;

  case 1258:
#line 3899 "sql_yacc.yy"
    {
	    Lex->ssl_type=SSL_TYPE_NONE;
	  }
    break;

  case 1259:
#line 3905 "sql_yacc.yy"
    {}
    break;

  case 1261:
#line 3909 "sql_yacc.yy"
    {}
    break;

  case 1262:
#line 3910 "sql_yacc.yy"
    {}
    break;

  case 1263:
#line 3913 "sql_yacc.yy"
    { Lex->grant |= GRANT_ACL;}
    break;

  case 1264:
#line 3915 "sql_yacc.yy"
    {
	  Lex->mqh.questions=yyvsp[0].ulong_num;
	  Lex->mqh.bits |= 1;
	}
    break;

  case 1265:
#line 3920 "sql_yacc.yy"
    {
	  Lex->mqh.updates=yyvsp[0].ulong_num;
	  Lex->mqh.bits |= 2;
	}
    break;

  case 1266:
#line 3925 "sql_yacc.yy"
    {
	  Lex->mqh.connections=yyvsp[0].ulong_num;
	  Lex->mqh.bits |= 4;
	}
    break;

  case 1267:
#line 3931 "sql_yacc.yy"
    { Lex->sql_command = SQLCOM_BEGIN;}
    break;

  case 1268:
#line 3931 "sql_yacc.yy"
    {}
    break;

  case 1269:
#line 3935 "sql_yacc.yy"
    {}
    break;

  case 1270:
#line 3936 "sql_yacc.yy"
    {;}
    break;

  case 1271:
#line 3939 "sql_yacc.yy"
    { Lex->sql_command = SQLCOM_COMMIT;}
    break;

  case 1272:
#line 3943 "sql_yacc.yy"
    {
	  Lex->sql_command = SQLCOM_ROLLBACK;
	}
    break;

  case 1273:
#line 3947 "sql_yacc.yy"
    {
	  Lex->sql_command = SQLCOM_ROLLBACK_TO_SAVEPOINT;
	  Lex->savepoint_name = yyvsp[0].lex_str.str;
	}
    break;

  case 1274:
#line 3953 "sql_yacc.yy"
    {
	  Lex->sql_command = SQLCOM_SAVEPOINT;
	  Lex->savepoint_name = yyvsp[0].lex_str.str;
	}
    break;

  case 1275:
#line 3964 "sql_yacc.yy"
    {}
    break;

  case 1277:
#line 3969 "sql_yacc.yy"
    {
	  LEX *lex=Lex;
	  if (lex->exchange)
	  {
	    /* Only the last SELECT can have  INTO...... */
	    net_printf(&lex->thd->net, ER_WRONG_USAGE,"UNION","INTO");
	    YYABORT;
	  }
	  if (lex->select->linkage == NOT_A_SELECT)
	  {
	    send_error(&lex->thd->net, ER_SYNTAX_ERROR);
	    YYABORT;
	  }
	  if (mysql_new_select(lex))
	    YYABORT;
	  lex->select->linkage=UNION_TYPE;
	}
    break;

  case 1278:
#line 3986 "sql_yacc.yy"
    {}
    break;

  case 1279:
#line 3990 "sql_yacc.yy"
    {}
    break;

  case 1280:
#line 3991 "sql_yacc.yy"
    {}
    break;

  case 1281:
#line 3997 "sql_yacc.yy"
    {}
    break;

  case 1282:
#line 3999 "sql_yacc.yy"
    {
    	    LEX *lex=Lex;
	    if (!lex->select->braces)
	    {
	      send_error(&lex->thd->net, ER_SYNTAX_ERROR);
	      YYABORT;
	    }
	    if (mysql_new_select(lex))
	      YYABORT;
	    mysql_init_select(lex);
	    lex->select->linkage=NOT_A_SELECT;
	    lex->select->select_limit=lex->thd->variables.select_limit;
	  }
    break;

  case 1284:
#line 4016 "sql_yacc.yy"
    {}
    break;

  case 1285:
#line 4017 "sql_yacc.yy"
    { Lex->union_option=1; }
    break;


    }

/* Line 1016 of /usr/share/bison/yacc.c.  */
#line 15517 "y.tab.c"

  yyvsp -= yylen;
  yyssp -= yylen;


#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("parse error, unexpected ") + 1;
	  yysize += yystrlen (yytname[yytype]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "parse error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("parse error");
    }
  goto yyerrlab1;


/*----------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action.  |
`----------------------------------------------------*/
yyerrlab1:
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* Return failure if at end of input.  */
      if (yychar == YYEOF)
        {
	  /* Pop the error token.  */
          YYPOPSTACK;
	  /* Pop the rest of the stack.  */
	  while (yyssp > yyss)
	    {
	      YYDPRINTF ((stderr, "Error: popping "));
	      YYDSYMPRINT ((stderr,
			    yystos[*yyssp],
			    *yyvsp));
	      YYDPRINTF ((stderr, "\n"));
	      yydestruct (yystos[*yyssp], *yyvsp);
	      YYPOPSTACK;
	    }
	  YYABORT;
        }

      YYDPRINTF ((stderr, "Discarding token %d (%s).\n",
		  yychar, yytname[yychar1]));
      yydestruct (yychar1, yylval);
      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */

  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      YYDPRINTF ((stderr, "Error: popping "));
      YYDSYMPRINT ((stderr,
		    yystos[*yyssp], *yyvsp));
      YYDPRINTF ((stderr, "\n"));

      yydestruct (yystos[yystate], *yyvsp);
      yyvsp--;
      yystate = *--yyssp;


#if YYDEBUG
      if (yydebug)
	{
	  short *yyssp1 = yyss - 1;
	  YYFPRINTF (stderr, "Error: state stack now");
	  while (yyssp1 != yyssp)
	    YYFPRINTF (stderr, " %d", *++yyssp1);
	  YYFPRINTF (stderr, "\n");
	}
#endif
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;


  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 609 "sql_yacc.yy"

