#ifndef NASL_PREPARSE_H__
#define NASL_PREPARSE_H__
int nasl_load_or_parse(naslctxt* ctx, const char* name1, const char * basename, const char * cache_dir);

int nasl_load_parsed_tree_buf(naslctxt * naslctx, char* buf, unsigned int len, const char * fname);

int nasl_parse_and_dump(const char* name1, const char * basename, const char * cache_dir);

#endif
