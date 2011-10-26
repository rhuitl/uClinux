/*
 * $Id: defines.h,v 1.8 2004/05/31 16:08:41 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Various macros, OS-independent types, and so on, are to be declared here.
 *
 */

#ifndef DEFINES_INCLUDED
#define DEFINES_INCLUDED

#include <limits.h>

/* Nonspecific limits */

#ifndef UCHAR_MAX
 #define UCHAR_MAX               255
#endif
#ifndef CHAR_BIT
 #define CHAR_BIT                  8
#endif
#ifndef LONG_MAX
 #define LONG_MAX        0x7FFFFFFFL
#endif

/* Archive header definitions */

#define MAXMETHOD                  4    /* v 0.14+ */

#define ARJ_VERSION               11    /* Current revision */
#define ARJ_ANSI_VERSION           9    /* Version that introduced ANSI CP
                                           (ARJ32 v 3.00-18/12/1998 ONLY!) */
#define ARJ_M_VERSION              6    /* ARJ version that supports archive
                                           last modification date. */
#define ARJ_X_VERSION              1    /* decoder version */
#define ARJ_G_VERSION              9    /* enhanced garble version */
#define ARJ_NEWCRYPT_VERSION      10    /* New encryption standard version */
#define ARJ_XD_VERSION             3    /* Version of decoder that supports
                                           directories */
#define ARJ_XU_VERSION            11    /* Version of decoder with UNIX support */
#define ARJ_X_SUPPORTED           11    /* Currently supported level
                                           (8 in official branch as of v 2.76) */
#define ARJ_X_SFX                 11    /* Level supported by ARJSFX
                                           (5 in official branch as of v 2.76) */
#define ARJSEC_VERSION             2    /* Current ARJ-SECURITY version */
#define DEFAULT_METHOD             1
#define DEFAULT_TYPE               0    /* if type_sw is selected */
#define HEADER_ID             0xEA60
#define HEADER_ID_HI            0xEA
#define HEADER_ID_LO            0x60
#define FIRST_HDR_SIZE            30
#define FIRST_HDR_SIZE_V          34

#define EA_ID                    'E'    /* EA ID in extended header */
#define UXSPECIAL_ID             'U'    /* UNIX special file ID */
#define OWNER_ID                 'O'    /* Owner ID */
#define OWNER_ID_NUM             'o'    /* Numeric owner ID */

/* NLS */

#define LANG_en                    0    /* English */
#define LANG_fr                    1    /* French */
#define LANG_de                    2    /* German */
#define LANG_ru                    3    /* Russian */

/* Registration-related data */

#define REG_ID                0xABC0    /* Indicates a registered ARJSFX */
#define UNREG_ID              0x1234    /* Indicates an unregistered ARJSFX */
#define REG_HDR_SHIFT             20    /* Bytes to skip after signature */
#define REG_HDR_LEN               32    /* Header size */
#define REG_KEY1_SHIFT (REG_HDR_SHIFT+REG_HDR_LEN)
#define REG_KEY1_LEN              10    /* Registration key #1 */
#define REG_KEY2_SHIFT (REG_KEY1_SHIFT+REG_KEY1_LEN)
#define REG_KEY2_LEN              10    /* Registration key #2 */
#define REG_NAME_SHIFT (REG_KEY2_SHIFT+REG_KEY2_LEN)
#define REG_NAME_LEN             100    /* Registration name */
#define STD_REG_LEN              152    /* Length of the registration field */
#define ARJSEC_RECORD_SIZE       120    /* Size of ARJ-SECURITY tail */
#define ARJSEC_ITER             1021    /* # of encryption iterations */

/* Explicit delays */

#define BAD_CRC_DELAY              5    /* Integrity violations */
#define SECURITY_DELAY             5    /* ARJ-SECURITY violations */
#define STD_CHANGE_VOL_DELAY      10    /* Default delay when changing
                                           volumes */

/* Header flags */

#define GARBLED_FLAG            0x01
#define OLD_SECURED_FLAG        0x02
#define ANSICP_FLAG             0x02    /* Matches with the ARJSEC v 1.x */
#define VOLUME_FLAG             0x04
#define EXTFILE_FLAG            0x08
#define PROT_FLAG               0x08    /* Main header only (v 3.02+) */
#define PATHSYM_FLAG            0x10
#define BACKUP_FLAG             0x20
#define SECURED_FLAG            0x40
#define DUAL_NAME_FLAG          0x80    /* ARJ v 2.55+ ("-hf1" mode) */

/* Extended header flags.
   The following encryption flags can NOT be OR'ed together! */

#define ENCRYPT_OLD                0    /* Standard encryption in pre-2.60 */
#define ENCRYPT_STD                1    /* Standard ARJ encryption */
#define ENCRYPT_GOST256            2    /* GOST 256-bit encryption (2.55+) */
#define ENCRYPT_GOST256L           3    /* GOST 256-bit encryption (2.62d+)
                                           allows 64-byte long passwords */
#define ENCRYPT_GOST40             4    /* GOST 40-bit encryption (2.61+) */
#define ENCRYPT_UNK               16    /* To be encrypted */

/* Relocated flags */

#define SFXSTUB_FLAG               1    /* Indicates SFXSTUB presence */

/* Limits to ARJ archives */

#define COMMENT_MAX             2048
#define EXTENSION_MAX              9    /* For internal procedures */
#define HEADERSIZE_MAX             (FIRST_HDR_SIZE+10+FILENAME_MAX+COMMENT_MAX)
#define CHAPTERS_MAX             250    /* Limited by 1 byte for chapter # */
#define RESERVED_CHAPTER       32764    /* For special markers */
#define HIGHEST_CHAPTER (RESERVED_CHAPTER+1)
#define MAX_FILE_SIZE       LONG_MAX    /* Size of compressed file */

/* Encoding/decoding constants */

#define CODE_BIT                  16
#define THRESHOLD                  3
#define DICSIZ                 26624
#ifdef TILED
 #define FDICSIZ              DICSIZ
#else
 #define FDICSIZ               32768    /* decode_f() dictionary size */
#endif
#define DICSIZ_MAX             32750
#define BUFSIZ_DEFAULT         16384
#define MAXDICBIT                 16
#define MATCHBIT                   8
#define MAXMATCH                 256
#define NC (UCHAR_MAX+MAXMATCH+2-THRESHOLD)
#define NP             (MAXDICBIT+1)
#define CBIT                       9
#define NT              (CODE_BIT+3)
#define PBIT                       5
#define TBIT                       5

#if NT>NP
#define NPT NT
#else
#define NPT NP
#endif

#define CTABLESIZE              4096
#define PTABLESIZE               256

#define STRTP                      9
#define STOPP                     13

#define STRTL                      0
#define STOPL                      7

#define PUTBIT_SIZE              512

#define MIN_CRITICAL_BUFSIZ      512    /* The minimum size allowed by the
                                           implementation */
#define MIN_BUFSIZ              2048
#define MAX_BUFSIZ       FAR_BLK_MAX
#define MAX_USER_BUFSIZ        65535    /* This one is here for compatibility:
                                           even if compiler doesn't allow such
                                           large values, the user should know
                                           nothing. */
#define BUFSIZ_INCREMENT           6

/* Message section defines */

#define MSGTEXT_MAX              512    /* Maximum length of individual msg
                                           (for copying far messages). It's
                                           allowed for near FMSGs to be
                                           larger */

/* Search defines */

#define SEARCH_STR_MAX            20    /* Maximum number of search patterns */

/* Extended wildcard return status */

#define XW_NONE                    0    /* No wildcards */
#define XW_OK                      1    /* Indicates successful parsing */
#define XW_PREM_END                2    /* Premature end of string */
#define XW_OWC                     3    /* Open * wildcard */
#define XW_UNPROC                  4    /* Unexpected unprocessed character */
#define XW_MISMATCH                5    /* Comparison mismatch */
#define XW_TERM                    6    /* Wildcard termination */
#define XWP_NONE                   0    /* Parsing was pointless */
#define XWP_TERM                  -1    /* Terminating '^' */
#define XWP_MDASH                 -2    /* Dash clause: -] or - */
#define XWP_OBRACKET              -3    /* Open bracket: [ */
#define XWP_NBRACKET              -4    /* Null bracket pair: [] */

/* Block operations */

#define BOP_NONE                   0    /* No action */
#define BOP_LIST                   1    /* List files to stdout ("arj s") */
#define BOP_SEARCH                 2    /* Search for a pattern ("arj w") */
#define BOP_COMPARE                3    /* Compare against disk files */
#define BOP_DISPLAY                5    /* List without pause */

/* Changing it would result in loss of compatibility: */

#define CRC_MASK         0xFFFFFFFFL

/* Console definitions */

#define CONSOLE_LINE_LENGTH       80    /* Length of output lines */

/* File types and limitations */

#define ARJT_BINARY                0
#define ARJT_TEXT                  1
#define ARJT_COMMENT               2
#define ARJT_DIR                   3
#define ARJT_LABEL                 4
#define ARJT_CHAPTER               5    /* Chapter mark - ARJ v 2.50+ */
#define ARJT_UXSPECIAL             6    /* UNIX special file - ARJ v 2.77+ */
#define TEXT_LCHAR                 7    /* Minimum displayable character */
#define TEXT_UCHAR               127    /* Maximum displayable character */
#define MIN_TEXT_SIZE            128    /* Minimum size for text files */

/* ARJ commands */

#define ARJ_CMD_ADD       ((int)'A')    /* Add files to archive */
#define ARJ_CMD_EXEC      ((int)'B')    /* Execute command */
#define ARJ_CMD_COMMENT   ((int)'C')    /* Comment archive files */
#define ARJ_CMD_DELETE    ((int)'D')    /* Delete files from archive */
#define ARJ_CMD_EXTR_NP   ((int)'E')    /* Extract, removing paths */
#define ARJ_CMD_FRESHEN   ((int)'F')    /* Freshen files in archive */
#define ARJ_CMD_GARBLE    ((int)'G')    /* Garble files in archive */
#define ARJ_CMD_CHK_INT   ((int)'I')    /* Check integrity */
#define ARJ_CMD_JOIN      ((int)'J')    /* Join archives */
#define ARJ_CMD_REM_BAK   ((int)'K')    /* Remove obsolete backup files */
#define ARJ_CMD_LIST      ((int)'L')    /* List archive contents */
#define ARJ_CMD_MOVE      ((int)'M')    /* Move files to archive */
#define ARJ_CMD_RENAME    ((int)'N')    /* Rename files in archive */
#define ARJ_CMD_ORDER     ((int)'O')    /* Order archive files */
#define ARJ_CMD_PRINT     ((int)'P')    /* List contents */
#define ARJ_CMD_RECOVER   ((int)'Q')    /* Recover damaged archive */
#define ARJ_CMD_REMPATH   ((int)'R')    /* Remove paths from filenames */
#define ARJ_CMD_SAMPLE    ((int)'S')    /* List to screen w/pause */
#define ARJ_CMD_TEST      ((int)'T')    /* Test an archive */
#define ARJ_CMD_UPDATE    ((int)'U')    /* Update files in archive */
#define ARJ_CMD_V_LIST    ((int)'V')    /* Verbosely list contents of archive */
#define ARJ_CMD_WHERE     ((int)'W')    /* Text search */
#define ARJ_CMD_EXTRACT   ((int)'X')    /* Extract files from archive */
#define ARJ_CMD_COPY      ((int)'Y')    /* Copy archive with new options */
#define ARJ_CMD_SECURE    ((int)'Z')    /* Create a security envelope */
#define ARJ_CMD_ADDC      ((int)'1')    /* Add a file to chapter archive */
#define ARJ_CMD_CNVC      ((int)'2')    /* Convert archive to a chapter one */
#define ARJ_CMD_DELC      ((int)'3')    /* Delete a chapter */
#define ARJDISP_CMD_START ((int)'+')    /* Put ARJDISP banner */
#define ARJDISP_CMD_END   ((int)'-')    /* Clear ARJDISP screen */

/* Command line limits */

#define CMDLINE_MAX              512    /* Length of command-line options */

/* ARJ errorlevels */

#define ARJ_ERL_SUCCESS            0
#define ARJ_ERL_WARNING            1
#define ARJ_ERL_FATAL_ERROR        2
#define ARJ_ERL_CRC_ERROR          3
#define ARJ_ERL_ARJSEC_ERROR       4
#define ARJ_ERL_DISK_FULL          5
#define ARJ_ERL_CANTOPEN           6
#define ARJ_ERL_USER_ERROR         7
#define ARJ_ERL_NO_MEMORY          8
#define ARJ_ERL_NOT_ARJ_ARCHIVE    9
#define ARJ_ERL_XMS_ERROR         10
#define ARJ_ERL_BREAK             11
#define ARJ_ERL_TOO_MANY_CHAPTERS 12

/* ARJSFX errorlevels */

#define ARJSFX_ERL_SUCCESS         0
#define ARJSFX_ERL_ERROR           1

/* ARJSFXJR errorlevels */

#define ARJSFXJR_ERL_SUCCESS       0
#define ARJSFXJR_ERL_FATAL         1
#define ARJSFXJR_ERL_ERROR         2

/* REARJ errorlevels */

#define REARJ_ERL_SUCCESS          0
#define REARJ_ERL_WARNING          1    /* File not found or other warning */
#define REARJ_ERL_UNCONFIGURED     2    /* File is not a configured archive
                                           type */
#define REARJ_ERL_TGT_EXISTS       3    /* Target archive already exists */
#define REARJ_ERL_DISK_FULL        4    /* Not enough disk space */
#define REARJ_ERL_UPD_SKIPPED      5    /* User skipped or user did not select
                                           update option */
#define REARJ_ERL_UNPACK           6    /* UNPACK error */
#define REARJ_ERL_PACK             7    /* PACK error */
#define REARJ_ERL_DIRECTORIES      8    /* Target cannot support directories */
#define REARJ_ERL_COUNT            9    /* Wrong file count */
#define REARJ_ERL_SIZE            10    /* Wrong total size */
#define REARJ_ERL_INTERNAL        11    /* Internal archive REARJ error */
#define REARJ_ERL_RENAME          12    /* Rename archive error */
#define REARJ_ERL_VIRUS           13    /* Invoked /v command error (found a
                                           virus?) */
#define REARJ_ERL_OVERGROW        14    /* Output archive is larger */

/* REGISTER errorlevels */

#define REGISTER_ERL_SUCCESS       0
#define REGISTER_ERL_ERROR         1

/* Approx. EXE file sizes (currently unused) */

#define EXESIZE_ARJ          102400L
#define EXESIZE_ARJSFXV       30000L
#define EXESIZE_ARJSFX        14000L
#define EXESIZE_ARJSFXJR       9000L
#define EXESIZE_MINSFX         5000L    /* The smallest header prefix that
                                           is considered as SFX (actually
                                           checked as EXESIZE_MINSFX+1) */

/* Maximum # of bytes to search for an archive header signature */

#if TARGET==DOS
 #define HSLIMIT_ARJ         524288L
 #define HSLIMIT_ARJSFX      262144L
 #define HSLIMIT_ARJSFXJR    131072L
#elif TARGET==OS2&&defined(TILED)&&!defined(DEBUG)
 #define HSLIMIT_ARJ         320000L
 #define HSLIMIT_ARJSFX       66000L
 #define HSLIMIT_ARJSFXJR     18000L
#else
 #define HSLIMIT_ARJ       16777216L    /* ...so we don't know/care about it */
 #define HSLIMIT_ARJSFX     8188608L
 #define HSLIMIT_ARJSFXJR   4094304L
#endif

/* Standard queries */

#define QUERY_CRITICAL             0    /* Can't be disabled */
#define QUERY_APPEND               1    /* -jya */
#define QUERY_CREATE_DIR           2    /* -jyc */
#define QUERY_DELETE_N_FILES       3    /* -jyd */
#define QUERY_LOW_SPACE            4    /* -jyk */
#define QUERY_EXTRACT_RENAME       5    /* -jyn */
#define QUERY_OVERWRITE            6    /* -jyo */
#define QUERY_SCANNED_ENOUGH       8    /* -jys */
#define QUERY_NEXT_VOLUME          9    /* -jyv */
#define QUERY_UPDATE              11    /* -jy std */
#define QUERY_PRESS_ENTER         12    /* "Press ENTER" and default is OK */
#define QUERY_ARCH_OP             13    /* archive operations (garble, etc.) */
#define TOTAL_QUERIES             14    /* Query array size */

/* Standard replies */

#define REPLY_YES                  0
#define REPLY_NO                   1
#define REPLY_QUIT                 2
#define REPLY_ALL                  3
#define REPLY_SKIP                 4
#define REPLY_GLOBAL               5
#define REPLY_COMMAND              6
#define MAX_REPLY                  6

/* Progrss indicator states */

#define IND_NORMAL                 0
#define IND_NONE                   1
#define IND_GRAPH                  2
#define IND_PCT_GRAPH              3
#define IND_TOTAL_PCT              4
#define IND_TOTAL_GRAPH            5
#define IND_TOTAL_PCT_GRAPH        6
#define IND_TOTAL_PCT_LGRAPH       7    /* -i6 (undocumented in v 2.62c) */

/* Multivolume option settings */

#define MV_NONE                    0    /* No -v */
#define MV_STD                     1    /* Standard -v w/user defined size */
#define MV_AVAIL                   2    /* Volume size depends on free space */

/* Multivolume command execution settings */

#define MVC_NONE                   0    /* No command execution (default) */
#define MVC_RUN_CMD                1    /* Execute command (-vs) */
#define MVC_RUN_CMD_NOECHO         2    /* Run command w/no echo (-vz) */
#define MVC_DELETION               3    /* -vd (deletion) command */

/* -* option (quiet mode) settings */

#define ARJ_NO_QUIET               0    /* default */
#define ARJ_QUIET                  1    /* -* */
#define ARJ_SILENT                 2    /* -*1 */
#define ARJ_QUIET2                 3    /* -*2 */

/* Archive security states */

#define ARJSEC_NONE                0    /* No ARJ-SECURITY */
#define ARJSEC_SECURED             1    /* Security envelope is present */
#define ARJSEC_SIGNED              2    /* Security signature is present */

/* ARJ-SECURITY processing options */

#define ARJSECP_STD                0    /* Default */
#define ARJSECP_SKIP               1    /* Skip test of security envelope */
#define ARJSECP_SET_ERROR          2    /* Set error on envelope */

/* Filename matching levels */

#define FMM_STD                    0    /* Default */
#define FMM_FULL_PATH              1    /* Match using full pathnames (-p) */
#define FMM_SUBDIRS                2    /* Match pathname w/subdirs (-p1) */

/* LFN support modes */

#define LFN_DEFAULT                0    /* Default (no -hf) */
#define LFN_NONE                   1    /* Use short names only (-hf) */
#define LFN_DUAL_EXT               2    /* Extract to W95LNAME.NNN (-hf1) */
#define LFN_IGNORE                 3    /* Use LFNs in DOS (-hf2) */
#define LFN_DUAL                   4    /* Use dual-mode name storage (-hf3) */
#define LFN_ALL                    5    /* Set all files as LFNs (-hf4) */

/* Filelist storage classes */

#define BST_NONE                   0    /* No memory allocated */
#define BST_FAR                    1    /* Block is in the far memory */
#define BST_DISK                   2    /* Block is on the disk */
#define BST_XMS                    3    /* Block is in the XMS */

/* File search logging levels */

#define SEARCH_DEFAULT             0    /* Display everything */
#define SEARCH_BRIEF               1    /* Display nothing but totals (-hw) */
#define SEARCH_SHOW_NAMES          2    /* Display files w/matches (-hw1) */

/* GOST encryption modes */

#define GOST_NONE                  0    /* No GOST encryption */
#define GOST256                    1    /* 256-bit encryption (2.55+) */
#define GOST40                     2    /* 40-bit encryption (2.61+) */

/* Extract files containing the given text */

#define EXTM_NONE                  0    /* No match is required */
#define EXTM_MATCHING              1    /* Only extract matching files */
#define EXTM_MISMATCHING           2    /* Only extract files w/o matches */

/* -d (delete_processed) flags */

#define DP_NONE                    0    /* Do not delete processed files */
#define DP_STD                     1    /* Standard (-d) */
#define DP_ADD                     2    /* On adds */
#define DP_STD                     1    /* Standard (-d) - ask permission */
#define DP_ADD                     2    /* Same as "ARJ m" */
#define DP_ADD_TRUNC               3    /* Same as DP_ADD + truncate
                                           (ASR fix for 2.78-TCO) */
#define DP_EXTRACT                10    /* On extraction */

/* Chapter archive update mode */

#define CHAP_NONE                  0    /* No support for chapters */
#define CHAP_USE                   1    /* Create/update/extract chapters */
#define CHAP_REMOVE                2    /* Revert a chapter archive back */

/* SFX creation states */

#define SFXCRT_NONE                0    /* Do not create a SFX */
#define SFXCRT_SFX                 1    /* Create an ARJSFX/ARJSFXV EXE */
#define SFXCRT_SFXJR               2    /* Create an ARJSFXJR EXE */

/* SFX descriptive identifiers */

#define SFXDESC_NONSFX             0    /* Non-ARJSFX module */
#define SFXDESC_SFXJR              1    /* ARJSFXJR module */
#define SFXDESC_SFX                2    /* ARJSFX module */
#define SFXDESC_SFXV               3    /* ARJSFXV module */

#define SFXDESC_MIN    SFXDESC_SFXJR    /* Supported range of descriptors */
#define SFXDESC_MAX     SFXDESC_SFXV

/* Ignore CRC errors (-jr) */

#define ICE_NONE                   0    /* Strict header checking */
#define ICE_FORMAT                 1    /* Ignore header format errors */
#define ICE_CRC                    2    /* Ignore header CRC errors only */

/* Ignore archive open errors */

#define IAE_NONE                   0    /* All open errors result in failure */
#define IAE_ACCESS                 1    /* Ignore open access errors (-hq) */
#define IAE_NOTFOUND               2    /* Ignore not found errors (-hq1) */
#define IAE_ALL                    3    /* Ignore both of the above (-hq2) */

/* ANSI codepage handling options */

#define ANSICP_STD                 0    /* Standard processing (depends on
                                           host OS) */
#define ANSICP_CONVERT             1    /* Convert to OEM codepage (-hy) */
#define ANSICP_SKIP                2    /* Process only OEM archives (-hy1) */
#define ANSICP_USE_OEM             2    /* Process only OEM archives (-hy2) */
#define ANSICP_USE_ANSI            4    /* Process only ANSI archives (-hy3) */

/* "-h#" (append time stamp) options */

#define ATS_NONE                   0    /* Nothing to append */
#define ATS_DATE                   1    /* Append date string */
#define ATS_TIME                   2    /* Append time string */
#define ATS_DUAL                   3    /* Append day number and time */

/* Comment display settings */

#define CMTD_STD                   0    /* Standard comment handling style */
#define CMTD_PCMD                  1    /* Use P command to display ANSI */
#define CMTD_NONE                  2    /* Do not display comments */

/* Verbose settings */

#define VERBOSE_NONE               0    /* Default level */
#define VERBOSE_STD                1    /* -jv */
#define VERBOSE_ENH                2    /* -jv1 */

/* Update and freshen options */

#define UC_NONE                    0    /* None (default) */
#define UC_NEW_OR_NEWER            1    /* New + newer (-u) */
#define UC_NEW_OR_OLDER            2    /* New + older (-u1) */
#define UC_NEW_OR_DIFFERENT        3    /* New + different (-u2) */
#define UC_NEW_OR_CRC              4    /* New + CRC mismatch (-u3) */
#define FC_NONE                    0    /* None (default) */
#define FC_EXISTING                1    /* Existing (-f) */
#define FC_OLDER                   2    /* Older (-f1) */
#define FC_DIFFERENT               3    /* Different (-f2) */
#define FC_CRC                     4    /* CRC mismatch (-f3) */

/* Selectable file types */

#define FT_BINARY                  1    /* Binary (default) */
#define FT_TEXT                    2    /* Text */
#define FT_TEXT_FORCED             3    /* Forced text type */
#define FT_TEXT_GRAPHICS           4    /* Text with graphics */
#define FT_NO_OVERRIDE             0    /* No type specified */

/* Backup options (-jg) */

#define BS_NONE                    0    /* No respect to backup files */
#define BS_SELECT                  1    /* Select backup files */
#define BS_ONLY                    2    /* Select ONLY backup files */

/* Timestamp override modes */

#define ATO_NONE                   0    /* Default */
#define ATO_NEWEST                 1    /* Set to newest (-s) */
#define ATO_SAVE_ORIGINAL          2    /* Save original timestamp (-s1) */
#define ATO_SAVE_ARCHIVE           3    /* Save archive timestamp (-s2) */
#define ATO_SAVE_BOTH              4    /* Save both timestamps (-s3) */

/* Hollow mode settings */

#define HM_NONE                    0    /* Standard mode */
#define HM_CRC                     1    /* Store only the CRC */
#define HM_NO_CRC                  2    /* Store only date/size/attributes */
#define HM_RESTORE_ATTRS           3    /* Restore attributes */
#define HM_RESTORE_DATES           4    /* Restore dates */
#define HM_RESTORE_ALL             5    /* Restore both attributes and dates */

/* CRC testing (-jt) options */

#define TC_NONE                    0    /* No testing, default */
#define TC_ARCHIVE                 1    /* Test entire archive (-jt) */
#define TC_CRC_AND_CONTENTS        2    /* Test CRC and contents (-jt1) */
#define TC_ADDED_FILES             3    /* Test only added files (-jt2) */
#define TC_ATTRIBUTES              4    /* Test only fdate/fsize (-jt3) */

/* -2d (compatible Host OS) settings */

#define CHO_NATIVE                 0    /* Use native OS */
#define CHO_USE_DOS                1    /* Always set host OS to DOS */
#define CHO_COMMENT                2    /* Fix comments only */

/* Recovery options */

#define RB_NONE                    0    /* Default, exit on broken files */
#define RB_NORMAL                  1    /* Normal mode, skip CRC errors (-jr) */
#define RB_TIGHT                   2    /* Tight mode, skip header errors
                                           (-jr1) */

/* Path exclusion options */

#define EP_NONE                    0    /* Default, store the full path */
#define EP_PATH                    1    /* Exclude path */
#define EP_BASEDIR                 2    /* Exclude base directory */

/* Century handling options */

#define CENT_DEFAULT               0    /* Default century handling */
#define CENT_SKIP                  1    /* Skip century in dates (-2k) */
#define CENT_SMART                 2    /* Smart handling (-2k1) */

/* Owner storage options */

#define OWNSTG_NONE                0    /* No owner storage */
#define OWNSTG_CHAR                1    /* Store in character format */
#define OWNSTG_ID                  2    /* Store in UID/GID format */
#define OWNSTG_CHAR_GID            3    /* Character format + GID */

/* OS codes */

#define OS_DOS                     0    /* MS-DOS */
#define OS_PRIMOS                  1    /* PRIMOS */
#define OS_UNIX                    2    /* UNIX-like operating systems */
#define OS_AMIGA                   3    /* AMIGA */
#define OS_MACOS                   4    /* Macintosh */
#define OS_OS2                     5    /* OS/2, WSoD, Warp Server, eCS */
#define OS_APPLE                   6    /* Apple GS */
#define OS_ATARI                   7    /* ATARI ST */
#define OS_NEXT                    8    /* NeXT */
#define OS_VAX                     9    /* VAX/VMS */
#define OS_WIN95                  10    /* Windows 95/98 */
#define OS_WINNT                  11    /* Windows NT/2000 */
#define OS_WIN32            OS_WINNT    /* Since ARJ v 2.62c */

#define OS_SPECIAL            0xFFFF    /* Reserved for special handling */

/* Implementation-independent path separators */

#define PATHSEP_UNIX             '/'
#define PATHSEP_DOS             '\\'

/* List character */

#define LISTCHAR_DEFAULT         '!'

/* Time filtering capabilities */

#define TCHECK_NOTHING             0    /* Time is not checked */
#define TCHECK_FTIME               1    /* Last write time */
#define TCHECK_NDAYS               2    /* No older than N days */
#define TCHECK_CTIME               3    /* Creation time */
#define TCHECK_ATIME               4    /* Last access time */

#define NULL_TIME                 0L    /* Non-existent timestamp */

/* Attributes for tagging */

#define TAG_FILES             0x0000    /* All files (-hbf -> -hbndhrs) */
#define TAG_ARCH              0x0001    /* Files with FA_ARCH set (-hba) */
#define TAG_NOT_ARCH          0x0002    /* Files with FA_ARCH clear (-hbb) */
#define TAG_RDONLY            0x0004    /* Read-only files (-hbr) */
#define TAG_SYSTEM            0x0008    /* System files (-hbs) */
#define TAG_HIDDEN            0x0010    /* Hidden files (-hbf) */
#define TAG_DIREC             0x0020    /* Directories (-hbd) */
#define TAG_LABEL             0x0040    /* Volume labels (-hbl) */
#define TAG_CHAPTER           0x0080    /* Internal chapter labels (-hbc) */
#define TAG_NORMAL            0x0100    /* Normal files (-hbn) */
#define TAG_WINLFN            0x0200    /* Windows 95 long filenames (-hbw) */
#define TAG_UXSPECIAL         0x0400    /* UNIX special files (-hbu) */

#define TAG_LIST      "FABRSHDLCNWU"    /* Used in command prompt */

/* Archive attribute filtering */

#define FAA_NONE                   0    /* Ignore archive bit (default) */
#define FAA_BACKUP                 1    /* Backup changed files */
#define FAA_BACKUP_CLEAR           2    /* Backup changed, reset archive bits */
#define FAA_CLEAR                  3    /* only reset archive bits */
#define FAA_RESTORE_CLEAR          4    /* reset archive bit during restore */
#define FAA_EXCL_CLEAR             5    /* do not restore bits, reset arc */
#define FAA_SKIP_ATTRS             6    /* do not restore any file attributes */

/* LFN support state */

#define LFN_NOT_SUPPORTED          0    /* Running in pure DOS */
#define LFN_SUPPORTED              1    /* Default for '95s */
#define LFN_COMP                   2    /* Compatibility mode */

/* validate_path actions */

#define VALIDATE_ALL               0    /* Remove all relative specs */
#define VALIDATE_NOTHING           1    /* Do nothing */
#define VALIDATE_DRIVESPEC         2    /* Remove leading drive specs */

/* File flags in filelist table. Two different mappings existed in ARJSFXV and
   ARJ as of v 2.72 (eliminated 17/01/2001 -- ASR) */

#define FLFLAG_TO_PROCESS         0    /* To be processed */
#define FLFLAG_PROCESSED          1    /* Already processed */
#define FLFLAG_SKIPPED            2    /* Forced to skip */
#define FLFLAG_DELETED            3    /* Already deleted */

/* Special processing actions */

#define CFA_NONE                   0    /* No special processing */
#define CFA_REMPATH                1    /* Remove paths from filenames */
#define CFA_GARBLE                 2    /* Garble files */
#define CFA_MARK_INCREMENT         3    /* Marking for chapter archives... */
#define CFA_UNMARK                 4
#define CFA_MARK                   5
#define CFA_MARK_EXT               6
#define CFA_UNMARK_EXT             7
#define CFA_UNGARBLE               8    /* Decrypt files */

/* File list generation options */

#define FETCH_DEFAULT              0    /* Standard files */
#define FETCH_FILES                1    /* Hidden files, etc. */
#define FETCH_DIRS                 2    /* Same + directories */

/* Extension serialization types */

#define EXT_NO_SERIALIZE           0    /* Do not serialize extensions */
#define EXT_SUBSTITUTE             1    /* Substitute extension */
#define EXT_INSERT                 2    /* Insert number before extension */

/* Operations on final pass  */

#define FP_GARBLE               0x02    /* Encryption stamping */
#define FP_SECURITY             0x15    /* Security envelope creation */
#define FP_VOLUME               0x16    /* Multivolume processing */
#define FP_CHAPTER              0x17    /* Chapter operations */
#define FP_PROT                 0x18    /* ARJ-PROTECT recovery record */

/* Encryption id states */

#define ENCID_NONE                 0    /* Default */
#define ENCID_GARBLE               1    /* Garble operation */
#define ENCID_UNGARBLE             2    /* Ungarble operation */

/* Message section validation flag */

#define CHKMSG_NOSKIP              0    /* Process CRC32 accumulation */
#define CHKMSG_SFX_HELP            1    /* Display ARJSFX help */
#define CHKMSG_SKIP               -1    /* Skip CRC32 accumulation */

/* Hardlink suppression */

#define SHL_NONE                   0    /* Normal processing */
#define SHL_DROP                   1    /* Ignore (do not add/extract) */
#define SHL_SOFT                   2    /* Ignore on addition, replace
                                           w/symlinks upon extraction */

/* Directory recursion order */

#define RO_LAST                    0    /* Contents, then direntry */
#define RO_FIRST                   1    /* Direntry, then contents */

/* Multivolume processing definitions */

#define MULTIVOLUME_RESERVE      604    /* Number of bytes to subtract */
#define MULTIVOLUME_INCREMENT    500    /* Criteria of switching to next vol. */
#define MIN_VOLUME_SIZE       10000L    /* Minimal allowed volume size */
#define MAX_VOLUME_TRIES           9    /* Number of times to check if we can
                                           switch to the next volume */
#define MAX_VOLUME_FT_CHECKS       3    /* Number of times to check the file
                                           timestamp */

/* SFX definitions */

#define SFX_COMMAND_SIZE         126    /* Length of SFX options in comment
                                           (must be less than CHAR_MAX) */

/* Color highlighting */

#ifdef COLOR_OUTPUT
struct color_hl
{
 char color;
 char arg;
};
#endif

#define H_STD                      0    /* Standard text */
#define H_OPER                     1    /* Operation/progress counters */
#define H_HL                       2    /* Highlight */
#define H_SIG                      3    /* Signal */
#define H_ALERT                    4    /* Alert */
#define H_PROMPT                   5    /* Prompt */
#define H_COLORMASK             0x0F    /* Color index */
/* Flags */
#define H_WEAK                  0x10    /* After answering "NO" to the pause
                                           request, the user will be brought
                                           back to main processing loop */
#define H_NFMT                  0x20    /* Revert to H_STD for formatting
                                           areas (e.g. "%d files") */
#define H_FORCE                 0x40    /* Does not go off with "-*",
                                           needs "-*1" to be silenced */
#define H_ERR      (H_ALERT|H_FORCE)    /* Make error msgs visible */

/* Line feed is used many times so we prefer to declare is as public in
   ENVIRON.C and use far references to it: */

extern char simple_lf[];
#define lf simple_lf
extern char simple_cr[];
#define cr simple_cr

/* An extended file information structure */

struct disk_file_info
{
 struct file_properties file_properties;
 char name[1];                          /* Allocated dynamically */
};

/* Memory packing */

struct mempack
{
 char FAR *comp;
 char FAR *orig;
 unsigned int compsize;
 unsigned int origsize;
 int method;
};

#define MEMPACK_OVERHEAD           4    /* CRC32 (for now) */

#endif
