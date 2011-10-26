#ifndef __AUTHD_SYSLOG_h__
#define __AUTHD_SYSLOG_h__

#include <linux/autoconf.h>
#include <config/autoconf.h>
#include <syslog.h>

#ifdef SYSLOGS_AT_EMERG
#undef LOG_ALERT
#undef LOG_CRIT
#undef LOG_ERR
#undef LOG_WARNING
#undef LOG_NOTICE
#undef LOG_INFO
#undef LOG_DEBUG

#define LOG_ALERT	LOG_EMERG
#define LOG_CRIT	LOG_EMERG
#define LOG_ERR 	LOG_EMERG
#define LOG_WARNING	LOG_EMERG
#define LOG_NOTICE	LOG_EMERG
#define LOG_INFO	LOG_EMERG
#define LOG_DEBUG	LOG_EMERG
#endif

#endif
