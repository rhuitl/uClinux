/*
 * $Id: externs.h,v 1.5 2004/06/18 16:19:37 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Each public variable  defined in EXTERNS.C is declared here, so all modules
 * that include this file will have access to all public variables.
 *
 */

#ifndef EXTERNS_INCLUDED
#define EXTERNS_INCLUDED

#include <setjmp.h>

/* Obsolete/shared data */

extern char nullstr[];
extern char strform[];
extern char path_separators[];
extern char switch_chars[];
extern char arjtemp_spec[];
extern int error_occured;
extern char cmd_ac[];
extern char cmd_cc[];
extern char cmd_dc[];
extern char le_prompt[];
extern char vd_space[];
extern int file_packing;
extern char FAR *encblock_ptr;
extern char FAR *packblock_ptr;
extern unsigned int encmem_remain;
extern unsigned int packmem_remain;
extern unsigned int encmem_limit;
extern int ea_supported;
extern long ext_hdr_capacity;
extern struct ext_hdr FAR *eh;
extern int valid_ext_hdr;
extern unsigned int ea_size;
extern char *exe_name;

/* Exported data */

#if SFX_LEVEL>=ARJ||defined(REARJ)
extern unsigned char regdata[];
#endif
extern struct flist_root flist_order;
extern struct flist_root flist_archive;
extern struct flist_root flist_main;
extern struct flist_root flist_exclusion;
extern struct flist_root flist_ea;
extern struct flist_root flist_xea;
#if TARGET==UNIX
extern struct l_entries l_entries;
extern struct l_entries sl_entries;
#endif
extern int win32_platform;
extern int switch_char;
extern int display_totals;
extern unsigned int file_attr_mask;
extern int pattern_found;
extern int is_registered;
extern int in_key;
extern int is_commercial;
extern int lfn_supported;
extern int ext_hdr_flags;
extern int file_garbled;
extern int arch_wildcard_allowed;
extern int file_args;
extern int volume_flag_set;
extern int tmp_archive_used;
extern int method_specifier;
extern int primary_file_type;
extern int identical_filedata;
extern int ctrlc_not_busy;
extern int ignore_errors;
extern int ctrlc_processing;
extern int supply_comment_file;
extern int use_comment;
extern int assume_yes;
extern int extract_to_file;
extern int assign_work_directory;
extern int multivolume_option;
extern int allow_mv_update;
extern int beep_between_volumes;
extern int chk_arj_version;
extern int verbose_display;
extern int update_criteria;
extern int translate_unix_paths;
extern int type_override;
extern int timestamp_override;
extern int test_archive_crc;
extern int store_by_suffix;
extern int skip_ts_check;
extern int comment_display;
extern int lfn_mode;
extern int create_sfx;
extern int filter_attrs;
extern int select_backup_files;
extern int search_mode;
extern int keep_tmp_file;
extern int hollow_mode;
extern int restart_at_filename;
extern int quiet_mode;
extern int recurse_subdirs;
extern int ignore_crc_errors;
extern int set_string_parameter;
extern int query_for_each_file;
extern int protfile_option;
extern int arjprot_tail;
extern int prot_blocks;
extern int arjdisp_enabled;
extern int prompt_for_more;
extern int marksym_expansion;
extern int fnm_matching;
extern int rsp_per_line;
extern int gost_cipher;
extern int filter_older;
extern int filter_same_or_newer;
extern int new_files_only;
extern int nonexist_filespec;
extern int skip_switch_processing;
extern int disable_sharing;
extern int yes_on_all_queries;
extern int indicator_style;
extern int disable_arj_sw;
extern int skip_time_attrs;
extern int custom_method;
extern int max_compression;
extern int filelist_storage;
extern int create_list_file;
extern int listfile_err_opt;
extern int listchars_allowed;
extern int handle_labels;
extern int sign_with_arjsec;
extern int keep_tmp_archive;
extern int keep_bak;
extern int create_index;
extern int detailed_index;
extern int ignore_archive_errors;
extern int ignore_open_errors;
extern int clear_archive_bit;
extern int jh_enabled;
extern int help_issued;
extern int garble_enabled;
extern int lowercase_names;
extern int validate_style;
extern int freshen_criteria;
extern int chk_free_space;
extern int force_lfn;
extern int select_by_number;
extern int show_filenames_only;
extern int override_archive_exts;
extern int extm_mode;
extern int exit_after_count;
extern int start_at_ext_pos;
extern int start_with_seek;
extern int exclude_paths;
extern int exclude_files;
extern int arjsec_opt;
extern int run_cmd_at_start;
extern int delete_processed;
extern int debug_enabled;
extern int install_errhdl;
extern int chapter_mode;
extern int set_target_directory;
extern int serialize_exts;
extern int allow_any_attrs;
extern int filter_fa_arch;
extern int append_curtime;
extern char *time_str;
extern int use_ansi_cp;
extern int queries_assume_no[TOTAL_QUERIES];
extern int queries_assume_yes[TOTAL_QUERIES];
extern int accept_shortcut_keys;
extern int skip_next_vol_query;
extern int skip_scanned_query;
extern int overwrite_existing;
extern int skip_rename_prompt;
extern int skip_space_query;
extern int query_delete;
extern int prompt_for_mkdir;
extern int skip_append_query;
extern int kbd_cleanup_on_input;
extern int use_sfxstub;
extern int whole_files_in_mv;
extern int pause_between_volumes;
extern int inhibit_change_test;
extern int mv_cmd_state;
extern int ignore_pcase;
extern int no_file_activity;
extern int std_list_cmd;
extern int print_with_more;
extern int subdir_extraction;
extern int execute_cmd;
extern int change_vol_delay;
extern unsigned int left_trim;
extern char listchar;
extern int errorlevel;
extern unsigned int errors;
extern int lines_per_page;
extern int lines_scrolled;
extern int secondary_file_type;
extern unsigned int file_type;
extern int unpackable;
extern int fdisp_lines;
extern int reserve_size;
extern int bitcount;
extern FILE_COUNT av_total_files;
extern FILE_COUNT av_total_longnames;
extern FILE_COUNT exit_count;
extern FILE_COUNT split_files;
#if SFX_LEVEL>=ARJ
extern FILE_COUNT FAR *order;
extern char **f_arg_array;
#else
extern int order[PARAMS_MAX];
extern char *f_arg_array[PARAMS_MAX];
#endif
extern int params_max;
extern char *comment_file;
extern char *archive_cmt_name;
extern char *yes_query_list;
extern char *extraction_filename;
extern char *swptr_hv;
extern char *search_reserve;
extern char *search_str[SEARCH_STR_MAX];
extern char *filename_to_restart;
extern char *string_parameter;
extern char *arjdisp_ptr;
extern char *arjcrypt_name;
extern char *nonexist_name;
extern unsigned long garble_ftime;
extern char *index_name;
extern char *list_file;
extern char *swptr_t;
extern char *cmd_to_exec;
extern char *archive_suffixes;
extern char *mv_cmd;
#ifndef REARJ
extern char *timestr_older;
extern char *timestr_newer;
#endif
extern char *arj_env_name;
extern char *swptr_hm;
extern char *work_directory;
extern char *target_dir;
extern char *tmp_archive_name;
extern char *rsp_name;
#if SFX_LEVEL>=ARJSFXV
extern char *tmp_tmp_filename;
extern char *archive_name;
#else
extern char tmp_tmp_filename[FILENAME_MAX];
extern char archive_name[FILENAME_MAX];
#endif
extern char *arjsec_env_name;
extern char password_modifier;
extern char *garble_password;
extern char *archive_ext_list;
extern char *debug_opt;
extern char *start_cmd;
extern char *misc_buf;
extern char label_drive;
extern char *strcpy_buf;
extern unsigned char host_os;
extern char *out_buffer;
#if SFX_LEVEL>=ARJSFXV
extern char *header;
#else
extern char header[HEADERSIZE_MAX];
#endif
extern unsigned char byte_buf;
extern unsigned char subbitbuf;
extern FILE *new_stderr;
extern int user_wants_fail;
extern int resume_volume_num;
extern unsigned int ext_voldata;
extern int out_avail;
extern int out_bytes;
extern int total_chapters;
extern int chapter_to_process;
extern int current_chapter;
extern FILE_COUNT max_filenames;
extern unsigned int user_bufsiz;
extern unsigned int current_bufsiz;
extern unsigned short bitbuf;
extern FILE *tstream;
extern FILE *idxstream;
extern FILE *new_stdout;
extern FILE *atstream;
extern FILE *aostream;
extern FILE *encstream;
extern FILE *aistream;
extern unsigned long FAR *arch_hdr_index;
extern unsigned long last_hdr_offset;
extern long search_occurences[SEARCH_STR_MAX];
extern unsigned long ext_pos;
extern unsigned long arcv_ext_pos;
extern long uncompsize;
extern unsigned long compsize;
extern unsigned long origsize;
extern unsigned long av_uncompressed;
extern unsigned long av_compressed;
extern unsigned long total_size;
extern unsigned long total_written;
extern unsigned long minfree;
extern struct timestamp tested_ftime_older;
extern struct timestamp tested_ftime_newer;
extern unsigned long t_volume_offset;
extern unsigned long mv_reserve_space;
extern unsigned long volume_limit;
extern struct timestamp secondary_ftime;
extern struct timestamp ftime_max;
extern unsigned long disk_space_used;
extern unsigned long total_compressed;
extern unsigned long total_uncompressed;
extern unsigned long arjsec_offset;
extern unsigned long secured_size;
extern unsigned long cur_header_pos;
extern long main_hdr_offset;
extern char FAR *tmp_filename;
extern unsigned long volume_crc;
extern struct timestamp volume_ftime;
extern FILE *ofstream;
extern int recent_chapter;
extern unsigned int alloc_unit_size;
extern FILE_COUNT split_longnames;
extern FILE_COUNT total_longnames;
extern FILE_COUNT total_files;
extern FILE_COUNT comment_entries;
extern int max_chapter;
extern int force_volume_flag;
extern int sfx_desc_word;
extern int add_command;
extern int order_command;
extern int no_inarch;
extern int modify_command;
extern int continued_nextvolume;
extern int first_vol_passed;
extern int mvfile_type;
extern unsigned int volume_number;
extern int continued_prevvolume;
extern int encryption_applied;
extern int cmd_verb;
extern int security_state;
extern int ansi_codepage;
extern int dual_name;
extern unsigned long archive_size;
extern unsigned long resume_position;
extern unsigned long header_crc;
extern unsigned long file_crc;
extern unsigned char chapter_number;
extern unsigned char ext_flags;
extern unsigned short host_data;
extern unsigned short entry_pos;
extern struct timestamp ctime_stamp;
extern struct timestamp atime_stamp;
extern struct timestamp ftime_stamp;
extern struct file_mode file_mode;
extern unsigned int method;
extern unsigned char arj_flags;
extern unsigned char arj_x_nbr;
extern unsigned char arj_nbr;
extern unsigned char first_hdr_size;
extern unsigned int basic_hdr_size;
extern char *hdr_comment;
extern char *hdr_filename;
#if SFX_LEVEL>=ARJSFXV
extern char FAR *comment;
#else
extern char comment[COMMENT_MAX];
#endif
extern char filename[FILENAME_MAX];
extern struct file_properties properties;
extern unsigned char pt_len[NPT];
extern unsigned short left[2*NC-1];
extern unsigned short right[2*NC-1];
extern unsigned char c_len[NC];
extern unsigned short cpos;
extern unsigned int bufsiz;
#if SFX_LEVEL>=ARJSFXV
extern unsigned char *dec_text;
#elif (!defined(REARJ))
extern unsigned char dec_text[DICSIZ];
#endif
#if SFX_LEVEL>=ARJ
extern unsigned char *ntext;
#endif

#if SFX_LEVEL>=ARJ
extern int arcmail_sw;
extern int dos_host;
extern struct priority priority;
extern int include_eas;
extern int exclude_eas;
extern int disable_comment_series;
extern int skip_century;
extern int fix_longnames;
extern int crit_eas;
extern int symlink_accuracy;
extern int do_chown;
extern int suppress_hardlinks;
extern int recursion_order;
extern int encryption_id;
extern jmp_buf main_proc;
#endif

#if SFX_LEVEL<=ARJSFXV
extern int valid_envelope;
extern int skip_integrity_test;
extern int prompt_for_directory;
extern int extract_expath;
extern int process_lfn_archive;
extern int skip_preset_options;
extern int list_sfx_cmd;
extern int overwrite_ro;
extern int test_sfx_cmd;
extern int verbose_list;
extern int extract_cmd;
extern int skip_volumes;
extern int first_volume_number;
extern int execute_extr_cmd;
extern int skip_extract_query;
extern char *extr_cmd_text;
extern unsigned short reg_id;
extern int licensed_sfx;
extern int logo_shown;
#endif

#if SFX_LEVEL<=ARJSFX
extern int make_directories;
extern int show_ansi_comments;
extern char *list_adapted_name;
extern int test_mode;
extern int sflist_args;
extern char *sflist[SFLIST_MAX];
#endif

#ifdef COLOR_OUTPUT
extern int redirected;
extern int no_colors;
extern struct color_hl color_table[];
#endif

#endif
