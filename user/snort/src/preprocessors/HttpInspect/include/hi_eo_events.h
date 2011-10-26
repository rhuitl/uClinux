#ifndef __HI_EO_EVENTS_H__
#define __HI_EO_EVENTS_H__

#include "hi_include.h"

/*
**  Client Events
*/
#define HI_EO_CLIENT_ASCII          0   /* done */
#define HI_EO_CLIENT_DOUBLE_DECODE  1   /* done */
#define HI_EO_CLIENT_U_ENCODE       2   /* done */
#define HI_EO_CLIENT_BARE_BYTE      3   /* done */
#define HI_EO_CLIENT_BASE36         4   /* done */
#define HI_EO_CLIENT_UTF_8          5   /* done */
#define HI_EO_CLIENT_IIS_UNICODE    6   /* done */
#define HI_EO_CLIENT_MULTI_SLASH    7   /* done */
#define HI_EO_CLIENT_IIS_BACKSLASH  8   /* done */
#define HI_EO_CLIENT_SELF_DIR_TRAV  9   /* done */
#define HI_EO_CLIENT_DIR_TRAV       10  /* done */
#define HI_EO_CLIENT_APACHE_WS      11  /* done */
#define HI_EO_CLIENT_IIS_DELIMITER  12  /* done */
#define HI_EO_CLIENT_NON_RFC_CHAR   13  /* done */
#define HI_EO_CLIENT_OVERSIZE_DIR   14  /* done */
#define HI_EO_CLIENT_LARGE_CHUNK    15  /* done */
#define HI_EO_CLIENT_PROXY_USE      16  /* done */
#define HI_EO_CLIENT_WEBROOT_DIR    17  /* done */

/*
**  IMPORTANT:
**  Every time you add a client event, this number must be
**  incremented.
*/
#define HI_EO_CLIENT_EVENT_NUM      18

/*
**  These defines are the alert names for each event
*/
#define HI_EO_CLIENT_ASCII_STR                          \
    "(http_inspect) ASCII ENCODING"
#define HI_EO_CLIENT_DOUBLE_DECODE_STR                  \
    "(http_inspect) DOUBLE DECODING ATTACK"
#define HI_EO_CLIENT_U_ENCODE_STR                       \
    "(http_inspect) U ENCODING"
#define HI_EO_CLIENT_BARE_BYTE_STR                      \
    "(http_inspect) BARE BYTE UNICODE ENCODING"
#define HI_EO_CLIENT_BASE36_STR                         \
    "(http_inspect) BASE36 ENCODING"    
#define HI_EO_CLIENT_UTF_8_STR                          \
    "(http_inspect) UTF-8 ENCODING"
#define HI_EO_CLIENT_IIS_UNICODE_STR                    \
    "(http_inspect) IIS UNICODE CODEPOINT ENCODING"
#define HI_EO_CLIENT_MULTI_SLASH_STR                    \
    "(http_inspect) MULTI_SLASH ENCODING"
#define HI_EO_CLIENT_IIS_BACKSLASH_STR                 \
    "(http_inspect) IIS BACKSLASH EVASION"
#define HI_EO_CLIENT_SELF_DIR_TRAV_STR                  \
    "(http_inspect) SELF DIRECTORY TRAVERSAL"
#define HI_EO_CLIENT_DIR_TRAV_STR                       \
    "(http_inspect) DIRECTORY TRAVERSAL"
#define HI_EO_CLIENT_APACHE_WS_STR                      \
    "(http_inspect) APACHE WHITESPACE (TAB)"
#define HI_EO_CLIENT_IIS_DELIMITER_STR                  \
    "(http_inspect) NON-RFC HTTP DELIMITER"
#define HI_EO_CLIENT_NON_RFC_CHAR_STR                   \
    "(http_inspect) NON-RFC DEFINED CHAR"
#define HI_EO_CLIENT_OVERSIZE_DIR_STR                   \
    "(http_inspect) OVERSIZE REQUEST-URI DIRECTORY"
#define HI_EO_CLIENT_LARGE_CHUNK_STR                    \
    "(http_inspect) OVERSIZE CHUNK ENCODING"
#define HI_EO_CLIENT_PROXY_USE_STR                      \
    "(http_inspect) UNAUTHORIZED PROXY USE DETECTED"
#define HI_EO_CLIENT_WEBROOT_DIR_STR                    \
    "(http_inspect) WEBROOT DIRECTORY TRAVERSAL"

/*
**  Anomalous Server Events
*/
#define HI_EO_ANOM_SERVER           0

#define HI_EO_ANOM_SERVER_EVENT_NUM 1

#define HI_EO_ANOM_SERVER_STR                           \
    "(http_inspect) ANOMALOUS HTTP SERVER ON UNDEFINED HTTP PORT"

/*
**  Event Priorities
*/
#define HI_EO_HIGH_PRIORITY 0
#define HI_EO_MED_PRIORITY  1
#define HI_EO_LOW_PRIORITY  2

#endif
