/*
 * $Id: externs.c,v 1.7 2004/06/18 16:19:37 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * All uninitialized  and initialized  variables that are  used by two or more
 * modules are defined here. Note that no separation is done for those used by
 * ARJ, ARJSFXV and so on...
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Auto-initializing variables */

#if SFX_LEVEL>=ARJSFXV
 #define AUTOINIT
#else
 #define AUTOINIT =0
#endif

/* Shared data, mostly the duplicate strings */

char nullstr[]="";                      /* Used instead of "" */
char strform[]="%s";                    /* printf(strform, str) */
char path_separators[]=PATH_SEPARATORS;
#if TARGET!=UNIX
 char switch_chars[]="-/";
#else
 char switch_chars[]="-";
#endif
#if SFX_LEVEL>=ARJ
char cmd_ac[]="AC";                     /* Chapter commands */
char cmd_cc[]="CC";
char cmd_dc[]="DC";
char arjtemp_spec[]="ARJTEMP.$%02d";    /* For all temporary files created */
char le_prompt[]="%02d> ";              /* String entry prompt */
#endif
#if SFX_LEVEL>=ARJSFXV
char vd_space[]="  ";                   /* ...after the filename */
#endif

/* Exported data */

#if SFX_LEVEL>=ARJ||defined(REARJ)

unsigned char regdata[]={'a', 'R', 'j', ' ', 's', 'O', 'f', 'T', 'w', 'A', 'r',
                         'E', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         '[', '/', '.', ',', ']', '$', '*', '(', '#', '@', '^',
                         '&', '*', '%', '#', '(', ')', 0};
#endif

#if SFX_LEVEL>=ARJSFXV
struct flist_root flist_order;          /* Order of files */
struct flist_root flist_archive;        /* Archives to be processed */
#endif
#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
struct flist_root flist_main;           /* Files to be processed */
struct flist_root flist_exclusion;      /* Files to be excluded */
#endif
#if SFX_LEVEL>=ARJ&&defined(HAVE_EAS)
struct flist_root flist_ea;             /* EAs to include */
struct flist_root flist_xea;            /* EAs to exclude */
#endif
#if SFX_LEVEL>=ARJ&&TARGET==UNIX
struct l_entries l_entries;
struct l_entries sl_entries;
#endif
int win32_platform;                     /* 1 if the archiver has been compiled
                                           for Win32 */
int display_totals;                     /* 1 if the total archive statistics
                                           can be shown in display_indicator() */
int switch_char AUTOINIT;               /* 1st switch character */
unsigned int file_attr_mask;            /* For optimization */
int pattern_found;                      /* 1 once the search pattern was found
                                           (m_w command) */
#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
int is_registered;                      /* 1 if the archiver is registered
                                           (this switch is inverted at the
                                           beginning to disallow hacking) */
int in_key;                             /* 1 = use the stored key */
#endif
#if SFX_LEVEL>=ARJ
int is_commercial;                      /* 1 if commercial version (in
                                           open-source world, means nothing) */
#endif
int lfn_supported AUTOINIT;             /* 1 if yes; set by detect_lfns */
int ext_hdr_flags;                      /* Extended flags, used in main ARJ
                                           archive header */
int file_garbled;                       /* 1 if the GARBLED_FLAG is set */
int arch_wildcard_allowed;              /* 1 if multiple archives can be
                                           processed */
int file_args AUTOINIT;                 /* Number of file arguments */
int volume_flag_set;                    /* 1 if the VOLUME_FLAG is set in the
                                           header */
#if SFX_LEVEL>=ARJ
int tmp_archive_used;                   /* Indicates that a temporary archive
                                           file was built */
int method_specifier;                   /* Number of the custom method */
int primary_file_type;                  /* Default type */
int identical_filedata;                 /* 1 if the files in archive are
                                           identical with the disk files */
#endif
#if SFX_LEVEL>=ARJSFXV
int ctrlc_not_busy;                     /* Ctrl+C handler can proceed */
int ignore_errors;                      /* 1 if everything is ignored (-hr) */
int ctrlc_processing;                   /* Ctrl+C is raised */
int supply_comment_file;                /* Supply file for comment (-jz) */
#endif
#if SFX_LEVEL>=ARJ
int use_comment;                        /* Supply archive comment (-z) */
#endif
int assume_yes;                         /* -jy option presence flag */
int extract_to_file;                    /* Extract to a single file (-jw) */
#if SFX_LEVEL>=ARJ
int assign_work_directory;              /* Set temporary directory (-w) */
#endif
int multivolume_option;                 /* 1 if the "-v" switch is issued */
#if SFX_LEVEL>=ARJ
int allow_mv_update;                    /* Allow update of multivolume archives */
int beep_between_volumes;               /* Beep between volumes (-vv) */
int chk_arj_version;                    /* -hv */
#endif
int verbose_display AUTOINIT;           /* State of verbose display (-jv) */
int update_criteria AUTOINIT;           /* Update option (-u), one of UC_* */
#if SFX_LEVEL>=ARJ
int translate_unix_paths;               /* Translate "/" path separators */
int type_override;                      /* File type override (-t) */
int timestamp_override;                 /* Archive time override (-s, ATO_*) */
int test_archive_crc;                   /* Test CRC (-jt, one of TC_*) */
int store_by_suffix;                    /* Store *.ZIP, *.ARJ, etc. */
#endif
int skip_ts_check AUTOINIT;             /* Skip timestamp check (-c) */
#if SFX_LEVEL>=ARJ
int comment_display;                    /* Comment display settings */
int lfn_mode;                           /* LFN handling mode (-hf) */
int create_sfx;                         /* !0 if the output file will be a SFX
                                           (the SFXCRT_* constants define the
                                           type of SFX) */
int filter_attrs;                       /* 1 if file are selected depending
                                           on their attributes (-hb) */
int select_backup_files;                /* Select backup files (-jg) */
int search_mode;                        /* File search logging level (-hw) */
#endif
int keep_tmp_file;                      /* Keep unprocessed file */
#if SFX_LEVEL>=ARJ
int hollow_mode;                        /* Create "hollow" archives (-j#) */
int restart_at_filename;                /* Restart volumes on filename (-jn) */
#endif
int quiet_mode AUTOINIT;                /* 1 or 2 if prompting is suppressed
                                           (registered ARJ only) */
int recurse_subdirs;                    /* Recurse thru subdirectories (-r) */
int ignore_crc_errors;                  /* One of ICE_* (-jr) */
#if SFX_LEVEL>=ARJ
int set_string_parameter;               /* Set command-line parameters */
int query_for_each_file;                /* 1 if yes (-q) */
int protfile_option;                    /* 1 if .XRJ file must be built (-hk) */
int arjprot_tail;                       /* Indicates presence of recovery
                                           record */
int prot_blocks;                        /* # of ARJ-PROTECT blocks */
#endif
int arjdisp_enabled AUTOINIT;           /* 1 if the ARJ$DISP interface is
                                           enabled (-hp) */
int prompt_for_more;                    /* 1 if the user is to be prompted
                                           when scrolling */
#if SFX_LEVEL>=ARJ
int marksym_expansion;                  /* Toggles expansion (see MISC.C) */
#endif
int fnm_matching AUTOINIT;              /* Filename matching mode, (FMM_*) */
int rsp_per_line;                       /* Set per-line RSP mode (-@) */
int gost_cipher;                        /* Garble via GOST 28147-89 (v 2.55+) */
int filter_older;                       /* Same and newer files are thrown away */
int filter_same_or_newer;               /* Older files are thrown away */
int new_files_only AUTOINIT;            /* Only the nonexistent files are OK */
int nonexist_filespec;                  /* Specify non-existing file (-hn) */
int skip_switch_processing AUTOINIT;    /* Set after "--" option */
int disable_sharing;                    /* 1 if SAA extended subs are used */
int yes_on_all_queries AUTOINIT;        /* 1 if all queries are skipped */
int indicator_style AUTOINIT;           /* -i indicator style (no enums) */
int disable_arj_sw;                     /* Disable ARJ_SW (-+) */
int skip_time_attrs;                    /* 1 to skip DTA/DTC handling (-j$) */
int custom_method;                      /* The value of -m, or 0 */
int max_compression;                    /* Maximal compression mode (-jm) */
int filelist_storage;                   /* Desired filelist storage method */
int create_list_file;                   /* -l */
int listfile_err_opt;                   /* Return error for list file error (-hhl) */
int listchars_allowed;                  /* 1 if yes */
int handle_labels;                      /* Should the labels be [re]stored
                                           (-$) */
int sign_with_arjsec;                   /* 1 if the archive must be sealed */
int keep_tmp_archive;                   /* Keep ARJTEMP on error (-jk) */
int keep_bak;                           /* Keep backup file (-k) */
int create_index;                       /* 1 if yes (-ji) */
int detailed_index;                     /* 1 if detailed index is to be built
                                           (-hi) */
int ignore_archive_errors;              /* 1 if an error like "Bad header" will
                                           not cause a termination */
int ignore_open_errors;                 /* Should the archive open errors on
                                           add operation be ignored? (-hq) */
int clear_archive_bit;                  /* 1 if chmod operations are used and
                                           all bits of file are set to 0 */
int jh_enabled;                         /* Nonzero if the "-jh" is used */
int help_issued AUTOINIT;               /* Help (-?) is issued by the user */
int garble_enabled;                     /* Garble with password */
int lowercase_names AUTOINIT;           /* Convert filenames being added or
                                           extracted to lower case */
int validate_style;                     /* VALIDATE_ALL, VALIDATE_NOTHING,
                                           or VALIDATE_DRIVESPEC */
int freshen_criteria AUTOINIT;          /* Freshen option (-f), one of FC_* */
int chk_free_space;                     /* Check space before extraction */
int force_lfn;                          /* Force LFN support (-h$) */
int select_by_number;                   /* Select files by number (-#) */
int show_filenames_only;                /* (-jl) Simplified display */
int override_archive_exts;              /* Set default archive extensions */
int extm_mode;                          /* Extract files w/matches (-ho) */
int exit_after_count;                   /* Exit after N files (-jc) */
int start_at_ext_pos;                   /* 1 if the -jx option was issued */
#if SFX_LEVEL>=ARJ
int start_with_seek;                    /* 1 if the -2i option was issued */
#endif
int exclude_paths;                      /* Exclude paths from filenames (-e) */
int exclude_files;                      /* Exclude selected files (-x) */
int arjsec_opt;                         /* -he options */
int run_cmd_at_start;                   /* Execute command on start (-hc) */
int delete_processed;                   /* Delete processed files (-d) */
int debug_enabled;                      /* 1 if yes */
int install_errhdl;                     /* Install critical error handler (-&) */
int chapter_mode;                       /* 0 - do not create chapters
                                           1 - create/process a chapter archive
                                           2 - dismiss chapter archive */
int set_target_directory;               /* Set target directory (-ht) */
int serialize_exts;                     /* Serialize extensions (-jo/-jo1) */
int allow_any_attrs;                    /* Allow any file attributes (-a) */
int filter_fa_arch;                     /* Store only files with 0x20 bit set */
int append_curtime;                     /* Append current date/time to archive
                                           filename (-h#) */
char *time_str;                         /* Time string to append */
int use_ansi_cp;                        /* Use ANSI codepage (-hy) */
#if SFX_LEVEL>=ARJ
int queries_assume_no[TOTAL_QUERIES];   /* 1 if NO is assumed as reply */
int queries_assume_yes[TOTAL_QUERIES];  /* 1 if YES is assumed as reply */
#endif
int accept_shortcut_keys;               /* Never used and defaults to 0 */
int skip_next_vol_query;                /* Skip "next volume...?" query */
int skip_scanned_query;                 /* Skip "scanned enough?" (-jys) */
int overwrite_existing AUTOINIT;        /* 1 if no prompt for overwriting an
                                           existing file is to be displayed */
int skip_rename_prompt;                 /* Skip "New name...?" prompt */
int skip_space_query;                   /* Skip free disk space query */
int query_delete;                       /* 1 if the user is to be queried when
                                           a set of files is to be deleted */
#if SFX_LEVEL>=ARJSFXV
int prompt_for_mkdir;                   /* 1 if yes (overrides -y) */
int skip_append_query;                  /* Skip "Append @ position..." query */
int kbd_cleanup_on_input;               /* Defaults to 0 */
#endif
#if SFX_LEVEL>=ARJSFXV
int use_sfxstub;                        /* Create multivolume stubbed
                                           packages */
#endif
#if SFX_LEVEL>=ARJ
int whole_files_in_mv;                  /* Store whole files in volumes (-vw) */
int pause_between_volumes;              /* Pause after completing volume
                                           (-vp) */
int inhibit_change_test;                /* Inhibit diskette change test (-vi) */
int mv_cmd_state;                       /* -vs/vz/vd commands -> MVC_* */
int ignore_pcase;                       /* Ignore case of search pattern */
#endif
#if SFX_LEVEL>=ARJ||defined(REARJ)
int no_file_activity;                   /* 1 if file writes can be ignored
                                           (-hdn in ARJ, -z in REARJ) */
#endif
int std_list_cmd AUTOINIT;              /* 1 if the standard (non-verbose) list
                                           is requested */
int print_with_more;                    /* Set to 1 if the ARJ P was called and
                                           the "more?" prompt is enabled */
int subdir_extraction;                  /* 1 if the ARJ x command was issued */
int execute_cmd;                        /* ARJ B sets this flag */
int change_vol_delay;                   /* Delay specified with -p */
unsigned int left_trim;                 /* Number of chars to remove from the
                                           beginning of filename during the
                                           extraction */
char listchar;                          /* Defaults to '!' */
int errorlevel;                         /* DOS errorlevel */
unsigned int errors AUTOINIT;           /* Number of errors */
int lines_per_page;                     /* Lines per screen for using "more" */
int lines_scrolled;                     /* Lines scrolled */
int secondary_file_type;                /* Type specified with a list */
unsigned int file_type;                 /* See DT_* equates */
int unpackable;                         /* 1 if the compressed file becomes
                                           greated than the original one */
int fdisp_lines;                        /* Lines to display in m_w command */
int reserve_size;                       /* Size of reserved buffer */
int bitcount;                           /* Temporary counter */
FILE_COUNT av_total_files;              /* Total # of files on all volumes */
FILE_COUNT av_total_longnames;          /* Total # of LFNs on all volumes */
FILE_COUNT exit_count;                  /* Number of files to exit after */
#if SFX_LEVEL>=ARJ
FILE_COUNT split_files;                 /* Number of files that span across
                                           volumes */
#endif
#if SFX_LEVEL>=ARJ
FILE_COUNT FAR *order;                  /* Order of files */
int params_max;
char **f_arg_array;
#else
int order[PARAMS_MAX];
int params_max=PARAMS_MAX;
char *f_arg_array[PARAMS_MAX];          /* Array of filename arguments */
#endif
char *comment_file;                     /* Global comment file */
char *archive_cmt_name;                 /* Archive comment (-z) filename */
char *yes_query_list;                   /* List of -jy parameters */
char *extraction_filename;              /* Filename specified by -jw */
char *swptr_hv;                         /* -hv parameter */
char *search_reserve;                   /* For strings that span across block
                                           boundaries */
#if SFX_LEVEL>=ARJ
char *search_str[SEARCH_STR_MAX];       /* Search patterns */
#endif
char *filename_to_restart;              /* Filename specified with -jn */
char *string_parameter;                 /* -jq string parameter */
char *arjdisp_ptr;                      /* -hp (ARJ$DISP switch) */
char *arjcrypt_name;                    /* ARJCRYPT.COM override (-hg) */
char *nonexist_name;                    /* Nonexistent filespec (-hn) */
unsigned long garble_ftime;             /* Used as a random seed when garbling
                                           files */
char *index_name;                       /* Index (-ji) filename */
char *list_file;                        /* -L list file */
char *swptr_t;                          /* -t (secondary file type list) */
char *cmd_to_exec;                      /* Text of command to be run */
char *archive_suffixes;                 /* A list of packed file extensions */
char *mv_cmd;                           /* Executed between volumes */
#ifndef REARJ
char *timestr_older;                    /* "-ob", "-oab", "-ocb" */
char *timestr_newer;                    /* "-o", "-ob", "-oc" */
#endif
char *arj_env_name;                     /* "ARJ_SW" or "ARJ32_SW" */
char *swptr_hm;                         /* -hm (file list management) */
char *work_directory;                   /* -w (work directory) override */
char *target_dir;                       /* Target directory, -ht overrides it */
char *tmp_archive_name;                 /* Back-up archive */
char *rsp_name;                         /* Response (@) filename */
/* Temporary filename storage */
#if SFX_LEVEL>=ARJSFXV
char *tmp_tmp_filename;
#else
char tmp_tmp_filename[FILENAME_MAX];
#endif
/* Archive filename with the extension added. */
#if SFX_LEVEL>=ARJSFXV
char *archive_name;
#else
char archive_name[FILENAME_MAX];
#endif
char *arjsec_env_name;                  /* ARJ-SECURITY envelope filename (-hz)
                                           Unused in noncommercial version */
char password_modifier;                 /* Garble password modifier */
char *garble_password;                  /* Pointer to garble password */
char *archive_ext_list;                 /* -hx extension list */
char *debug_opt;                         /* -hd (debug) */
char *start_cmd;                        /* Command to run at start */
char *misc_buf;                         /* allocated at main(). General-purpose
                                           buffer. */
char label_drive;                       /* Drive letter (-$A, -$B, etc.) */
char *strcpy_buf;                       /* allocated at main() */
unsigned char host_os;                  /* Host operating system of archive
                                           and source files within it. */
char *out_buffer;                       /* Temporary storage of encoded data */
/* ARJ header storage area */
#if SFX_LEVEL>=ARJSFXV
char *header;
#else
char header[HEADERSIZE_MAX];
#endif
unsigned char byte_buf;                 /* Used for preserving the data read */
unsigned char subbitbuf;                /* Backup storage */
int user_wants_fail;                    /* -1 if the user has manually
                                           cancelled the operation */
int resume_volume_num;                  /* -jn volume number */
unsigned int ext_voldata;               /* Size of additional (non-ARJ) data in
                                           multivolume archives */
int out_avail;                          /* Number of available bytes in
                                           out_buffer */
int out_bytes;                          /* Number of bytes pending */
int total_chapters;                     /* Number of chapters in the file */
int chapter_to_process;                 /* Number of chapter to be processed */
int current_chapter;                    /* Chapter number of current file */
FILE_COUNT max_filenames;               /* Initialized with 65000 by default */
unsigned int user_bufsiz;               /* The "-jh" value */
unsigned int current_bufsiz;            /* Size of the buffer, picked every time
                                           when the compressor starts */
unsigned short bitbuf;                  /* Used directly in the decoding */
FILE *new_stderr;                       /* Indicates presence of STDERR
                                           re-route */
FILE *tstream;                          /* Any disk file */
#if SFX_LEVEL>=ARJ
FILE *idxstream;                        /* Index file */
#endif
#if SFX_LEVEL>=ARJSFXV
FILE *new_stdout;                       /* stdout or stderr */
#endif
FILE *atstream=NULL;                    /* Temporary handle */
#if SFX_LEVEL>=ARJ
FILE *aostream;                         /* Archive output file handle */
FILE *encstream;                        /* The file being encoded */
#endif
FILE *aistream;                         /* Archive input file handle */
#if SFX_LEVEL>=ARJSFXV
unsigned long FAR *arch_hdr_index;      /* Contains offsets of archive files */
#endif
unsigned long last_hdr_offset;          /* Offset of last archive header */
#if SFX_LEVEL>=ARJ
long search_occurences[SEARCH_STR_MAX]; /* Number of occurences of each search
                                           pattern from search_str[] */
#endif
unsigned long ext_pos;                  /* Offset specified by -jx */
#if SFX_LEVEL>=ARJSFXV
unsigned long arcv_ext_pos;             /* Offset specified by -2i */
#endif
long uncompsize;                        /* Size of the file on the disk */
unsigned long compsize;                 /* Size of compressed data */
unsigned long origsize;                 /* Size of the source file */
unsigned long av_uncompressed;          /* Size of uncompressed data on all
                                           volumes */
unsigned long av_compressed;            /* Size of compressed data on all
                                           volumes */
unsigned long total_size;               /* Total size of all files to be
                                           archived */
unsigned long total_written;            /* Total size of all files that are
                                           archived, excluding the current. */
unsigned long minfree;                  /* Minimal disk space for operation
                                           (-jdxxx) */
struct timestamp tested_ftime_older;    /* Time attribute for filtering (<) */
struct timestamp tested_ftime_newer;    /* Time attribute for filtering (>=) */
unsigned long t_volume_offset;          /* Offset of multivolume data */
unsigned long mv_reserve_space;         /* Number of bytes to reserve on the
                                           first volume */
unsigned long volume_limit;             /* Maximum volume size in bytes */
struct timestamp secondary_ftime;       /* Used in rare occasions */
struct timestamp ftime_max;             /* Most recent timestamp of files
                                           contained within archive */
unsigned long disk_space_used;          /* Space allocated for the files */
unsigned long total_compressed AUTOINIT;/* Total size of compressed data */
/* Total size of uncompressed data */
unsigned long total_uncompressed AUTOINIT;
unsigned long arjsec_offset;            /* Offset of ARJ-security envelope */
unsigned long secured_size;             /* Original size of ARJ-secured file */
unsigned long cur_header_pos;           /* Offset of currently processed header
                                           within the archive */
long main_hdr_offset;                   /* Offset of main archive header
                                           (nonzero in SFX) */
#if SFX_LEVEL>=ARJSFXV
char FAR *tmp_filename;                 /* Backup copy of current filename */
#endif
unsigned long volume_crc;               /* CRC kept for multivolume files */
struct timestamp volume_ftime;          /* Multivolume ftime storage */
FILE *ofstream;                         /* -jw output file */
int recent_chapter;                     /* Chapter to be added, if any */
unsigned int alloc_unit_size;           /* Size of allocation unit */
FILE_COUNT split_longnames;             /* Number of cross-volume longnames */
FILE_COUNT total_longnames;             /* Number of processed files with LFN */
FILE_COUNT total_files AUTOINIT;        /* Number of processed files */
FILE_COUNT comment_entries;             /* Number of filenames acting as
                                           comment (e.g., chapter separators) */
int max_chapter;                        /* Maximum number of chapter found so
                                           far */
#if SFX_LEVEL>=ARJ
int force_volume_flag;                  /* 1 if the file will be marked with
                                           VOLUME_FLAG even if it is not
                                           multi-volume */
int sfx_desc_word;                      /* Descriptive word of SFX */
int add_command;                        /* 1 if the current operation adds any
                                           external files to the archive */
int order_command;                      /* An order command was issued */
#endif
int no_inarch;                          /* 1 if there's no input archive */
int modify_command;                     /* 1 if the current operation modifies
                                           the archive contents */
unsigned int volume_number;             /* .A0x, .Axx volume number */
int continued_nextvolume;               /* 1 if the file continues on the next
                                           volume (the VOLUME_FLAG is set ) */
int first_vol_passed;                   /* 1 once the first archive volume has
                                           been fully processed */
int mvfile_type;                        /* Types of multi-volume files */
int continued_prevvolume;               /* 1 if the resume_position must be
                                           taken into account (indicates that
                                           the file is split from a previous
                                           volume) */
#if SFX_LEVEL>=ARJSFXV
int encryption_applied;                 /* Encryption operation will occur */
#endif
int cmd_verb;                           /* ASCII code of the command issued
                                           (uppercase) */
int security_state AUTOINIT;            /* ARJSEC_* constants may be here */
int ansi_codepage;                      /* 1 if the archive filename is in the
                                           ANSI codepage. */
int dual_name AUTOINIT;                 /* 1 if dual-name mode (long filename
                                           is stored in the comment field, see
                                           help on "-hf1" for details) */
unsigned long archive_size;             /* Size of the whole archive, excluding
                                           the two terminating 0's */
unsigned long resume_position;          /* For multi-volume files, the number
                                           of bytes to skip. */
unsigned long header_crc;               /* CRC of current archive header */
unsigned long file_crc;                 /* CRC-32 of uncompressed file */
unsigned char chapter_number;           /* Chapter number, 1 to 250. */
unsigned char ext_flags;                /* Used for chapter number or extended
                                           header flags storage */
unsigned short host_data;               /* Used for chapter information */
unsigned short entry_pos;               /* Entryname position in filename */
struct timestamp ctime_stamp;           /* v 2.62+ - creation date/time */
struct timestamp atime_stamp;           /* v 2.62+ - last access date/time */
struct timestamp ftime_stamp;           /* Last modification date/time */
struct file_mode file_mode;             /* File access mode bit-map */
unsigned int method;                    /* Packing method */
unsigned char arj_flags;                /* Archive flags */
unsigned char arj_x_nbr;                /* Minimum version to extract */
unsigned char arj_nbr;                  /* Archiver version number */
unsigned char first_hdr_size;           /* Size of fixed-length header (30) */
unsigned int basic_hdr_size;            /* Size of the basic (not extended)
                                           header */
char *hdr_comment;                      /* Comment stored in the header */
char *hdr_filename;                     /* Filename stored in the header */
/* Preallocated comment storage area */
#if SFX_LEVEL>=ARJSFXV
char FAR *comment;
#else
char comment[COMMENT_MAX];
#endif
int use_comment;                        /* Supply archive comment (-z) */
char filename[FILENAME_MAX];            /* Filename storage buffer */
struct file_properties properties;      /* Properties of the current file */
int restart_at_filename;                /* Restart volumes on filename (-jn) */
#ifndef REARJ
unsigned char pt_len[NPT];              /* Prefix table length */
unsigned short left[2*NC-1];            /* Huffman tree */
unsigned short right[2*NC-1];           /* Huffman tree */
unsigned char c_len[NC];                /* Character length */
unsigned short cpos;                    /* Position in out_buffer */
unsigned int bufsiz;                    /* Size of the Huffman buffer, specified
                                           by "-jh" and adjusted afterwards */
#endif
#if SFX_LEVEL>=ARJSFXV
unsigned char *dec_text;
#elif !defined(REARJ)
unsigned char dec_text[DICSIZ];
#endif
/* The following is an ASR fix -- performance enhancement to 2.76.06 */
#if SFX_LEVEL>=ARJ
unsigned char *ntext;                   /* decode_f() non-volatile dictionary */
#endif

/* Missing or obsolete in original ARJ 2.62c */

#if SFX_LEVEL>=ARJSFXV
int error_occured;                      /* 1 if an error happened and ARJ must
                                           exit. */
#endif
int file_packing;                       /* 1 if uncompressed data is a file */
char FAR *encblock_ptr;                 /* Uncompressed data pointer */
char FAR *packblock_ptr;                /* Compressed data pointer */
unsigned int encmem_remain;             /* Amount of uncompressed data */
unsigned int packmem_remain;            /* Amount of compressed data */
unsigned int encmem_limit;              /* To prevent overruns */
#if SFX_LEVEL>=ARJSFXV
int ea_supported;                       /* Extended attributes support flag */
long ext_hdr_capacity;                  /* Number of RAW bytes to flush when
                                           writing the extended header on the
                                           current file portion. Must be
                                           SIGNED! */
struct ext_hdr FAR *eh;                 /* Extended header */
unsigned int ea_size;                   /* Size of unpacked EAs */
#endif
int valid_ext_hdr;                      /* Specifies that the extended header
                                           data can be processed */
char *exe_name;                         /* Name of executable invoked */
#if SFX_LEVEL>=ARJ
int arcmail_sw;                         /* ARCmail non-overwrite mode */
int dos_host;                           /* Use DOS as host OS under OS/2 */
struct priority priority;               /* Selectable process priority */
int include_eas;                        /* EA inclusion filelist is present */
int exclude_eas;                        /* EA exclusion filelist is present */
int disable_comment_series;             /* Apply comment to the 1st volume,
                                           strip it for all others */
int skip_century;                       /* Skip centuries in list commands */
int fix_longnames;                      /* 1 if .LONGNAME EAs should be
                                           resolved to filenames in headers */
int crit_eas;                           /* 1 if only critical EAs should
                                           be packed/restored */
int symlink_accuracy;                   /* Restore symlink properties */
int do_chown;                           /* Query / set the file owner */
int suppress_hardlinks;                 /* Store the whole copies */
int recursion_order;                    /* Directory recursion order */
int encryption_id;                      /* Identifies encryption in header */
jmp_buf main_proc;                      /* Entry point of archive processing
                                           loop */
#endif

/* ARJSFX data */

#if SFX_LEVEL<=ARJSFXV
int valid_envelope AUTOINIT;            /* 1 if the archive has a valid
                                           ARJ-SECURITY envelope */
int skip_integrity_test AUTOINIT;       /* Skip virus/security check (-a) */
int prompt_for_directory AUTOINIT;      /* Prompt for directory (-b) */
int extract_expath AUTOINIT;            /* Extract excluding paths (-e) */
int process_lfn_archive AUTOINIT;       /* Process a Windows LFN archive (-j) */
int skip_preset_options;                /* Skip preset SFX options (-k) */
int list_sfx_cmd AUTOINIT;              /* List SFX contents (-l) */
int overwrite_ro;                       /* Overwrite read-only files */
int test_sfx_cmd AUTOINIT;              /* Test archive (-t) */
int verbose_list AUTOINIT;              /* Verbose list command (-v) */
int extract_cmd AUTOINIT;               /* Default extract command (-x) */
#if SFX_LEVEL>=ARJSFXV
int skip_volumes;                       /* Skip over first volumes (-#) */
int first_volume_number;                /* First volume to process */
#endif
int execute_extr_cmd AUTOINIT;          /* Execute command upon extraction */
int skip_extract_query AUTOINIT;        /* Skip file extraction query (-ym) */
char *extr_cmd_text;                    /* Command to be run */
unsigned short reg_id AUTOINIT;         /* SFX registration signature */
int licensed_sfx AUTOINIT;              /* Indicates a licensed (secured) SFX */
int logo_shown AUTOINIT;                /* 1 once the ARJSFX logo is shown */
#endif

#if SFX_LEVEL<=ARJSFX
int make_directories AUTOINIT;          /* 1 if directory creation is allowed */
int show_ansi_comments AUTOINIT;        /* Display ANSI comments */
char *list_adapted_name;                /* Filename used in listing */
int test_mode AUTOINIT;                 /* 1 if test_sfx_cmd was issued */
int sflist_args AUTOINIT;               /* Simplified filelist -- # of args */
char *sflist[SFLIST_MAX];               /* Simplified filelist itself */
#endif

#ifdef COLOR_OUTPUT
int redirected;                         /* 1 if STDOUT was redirected */
int no_colors;                          /* 1 if color output was disabled */
struct color_hl color_table[]={
                               {7, 'n'},
                               {10, 'o'},
                               {2, 'h'},
                               {15, 's'},
                               {12, 'a'},
                               {3, 'p'},
                               {0, 0}
                              };
#endif
