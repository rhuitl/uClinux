
#define PACKAGE "dhcpcd"
#define VERSION "1.3.20-pl0"

// #define DebugSyslog(x, fmt...)
#define DebugSyslog(x, fmt...) if (DebugFlag) syslog(x, ##fmt); else

extern int DebugFlag;
