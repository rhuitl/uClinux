#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "cgiparse.h"
#include "netflash.h"
#include "exit_codes.h"

/*#define DEBUG_CGI*/

static char s_options[64];
static char s_flash_region[20];
static const char *s_data_name = 0;
static const char *s_options_name = 0;
static const char *s_flash_region_name = 0;
static size_t s_len = 0;

static void data_writer(const char *name, const char *content_type, const char *buf, size_t len, off_t pos)
{
	if (pos == 0 && len == 0) {
#ifdef DEBUG_CGI
		/*printf("\nSECTION: name=%s, type=%s\n", name, content_type);*/
		syslog(LOG_INFO, "SECTION: name=%s, type=%s", name, content_type);
#endif
	}
	else {
		if (strcmp(name, s_data_name) == 0) {
#ifdef DEBUG_CGI
			/*printf("add_data(pos=%d, len=%d)\n", pos, len);*/
			syslog(LOG_INFO, "add_data(pos=%ld, len=%d)\n", pos, len);
#endif
			local_write(-1, buf, len);
			s_len = pos + len;
		}
		else if (strcmp(name, s_options_name) == 0) {
			assert(len < sizeof(s_options));
			memcpy(s_options, buf, len);
			s_options[len] = 0;
#ifdef DEBUG_CGI
			/*printf("Got options: %s\n", s_options);*/
			syslog(LOG_INFO, "SECTION: options: %s = '%s'", name, s_options);
#endif
		}
		else if (strcmp(name, s_flash_region_name) == 0) {
			assert(len < sizeof(s_flash_region));
			memcpy(s_flash_region, buf, len);
			s_flash_region[len] = 0;
#ifdef DEBUG_CGI
			/*printf("Got flash_region: %s\n", s_flash_region);*/
			syslog(LOG_INFO, "SECTION: flash_region: %s = '%s'", name, s_flash_region);
#endif
		}
		else {
#ifdef DEBUG_CGI
			syslog(LOG_ERR, "Unknown cgi section: %s (options=%s)\n", name, s_options_name);
#endif
		}
	}
}

/**
 * Returns length of data if OK, or 0 if error.
 * Netflash error code is returned in error_code if applicable.
 * 
 */
size_t cgi_load(const char *data_name, const char *options_name, char options[64], const char *flash_region_name, char flash_region[20], int *error_code)
{
	int ret;

	s_data_name = data_name;
	s_options_name = options_name;
	s_flash_region_name = flash_region_name;

	ret = cgi_extract_sections(data_writer);
	switch (ret) {
	case CGIPARSE_ERR_NONE:
		strcpy(options, s_options);
		strcpy(flash_region, s_flash_region);
#ifdef DEBUG_CGI
		syslog(LOG_INFO, "Returning s_len=%d, options=%s, flash_region=%s", s_len, options, flash_region);
#endif
		/* Was an image specified? */
		if (s_len == 0) {
			*error_code = NO_IMAGE;
			return(0);
		}
		*error_code = IMAGE_GOOD;
		return(s_len);
		break;

	case CGIPARSE_ERR_FORMAT:
		*error_code = BAD_CGI_FORMAT;
		break;

	case CGIPARSE_ERR_DATA:
		*error_code = BAD_CGI_DATA;
		break;

	case CGIPARSE_ERR_TIMEDOUT:
		*error_code = HTTP_TIMEOUT;
		break;

	default:
		*error_code = BAD_CGI_DATA;
		break;
	}
	return(0);
}
