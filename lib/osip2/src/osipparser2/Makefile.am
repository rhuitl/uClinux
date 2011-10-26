
EXTRA_DIST = parser.h osip_rfc3264i.h

lib_LTLIBRARIES = libosipparser2.la

libosipparser2_la_SOURCES= osip_content_encoding.c osip_proxy_authorization.c \
osip_accept_encoding.c      osip_cseq.c                osip_record_route.c    \
osip_accept_language.c      osip_accept.c              osip_route.c           \
osip_alert_info.c           osip_error_info.c          osip_to.c              \
osip_allow.c                osip_from.c                osip_uri.c             \
osip_authorization.c        osip_header.c              osip_via.c             \
osip_body.c                 osip_md5c.c               osip_www_authenticate.c \
osip_call_info.c            osip_message.c             osip_list.c            \
osip_call_id.c              osip_message_parse.c                              \
osip_contact.c              osip_message_to_str.c      osip_port.c            \
osip_content_disposition.c  osip_mime_version.c        sdp_message.c          \
osip_content_length.c       osip_parser_cfg.c          sdp_accessor.c         \
osip_content_type.c         osip_proxy_authenticate.c  osip_rfc3264.c         \
osip_authentication_info.c  osip_proxy_authentication_info.c

libosipparser2_la_LDFLAGS = -version-info $(LIBOSIP_SO_VERSION) \
 $(PARSER_LIB) $(EXTRA_LIB)


INCLUDES = -I$(top_srcdir)/include
AM_CFLAGS = $(SIP_CFLAGS) $(SIP_PARSER_FLAGS) $(SIP_EXTRA_FLAGS)

