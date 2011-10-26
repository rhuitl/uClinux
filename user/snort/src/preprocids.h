#ifndef _PREPROC_IDS_H_
#define _PREPROC_IDS_H

/*
**  Preprocessor Communication Defines
**  ----------------------------------
**  These defines allow preprocessors to be turned
**  on and off for each packet.  Preprocessors can be
**  turned off and on before preprocessing occurs and
**  during preprocessing.
**
**  Currently, the order in which the preprocessors are
**  placed in the snort.conf determine the order of 
**  evaluation.  So if one module wants to turn off
**  another module, it must come first in the order.
*/
//#define PP_ALL                    0xffffffff
//#define PP_LOADBALANCING          1
//#define PP_PORTSCAN               2
#define PP_HTTPINSPECT            3
//#define PP_PORTSCAN_IGNORE_HOSTS  4
#define PP_RPCDECODE              5
#define PP_BO                     6
#define PP_TELNET                 7
#define PP_STREAM4                8
#define PP_FRAG2                  9
#define PP_ARPSPOOF               10
//#define PP_ASN1DECODE             11
//#define PP_FNORD                  12
//#define PP_CONVERSATION           13
//#define PP_PORTSCAN2              14
//#define PP_HTTPFLOW               15
#define PP_PERFMONITOR            16
//#define PP_STREAM4_REASSEMBLE     17
#define PP_FRAG3                  18
#define PP_FTPTELNET              19
#define PP_SMTP                   20
#define PP_SFPORTSCAN             21
#define PP_FLOW                   22
#define PP_ISAKMP                 23
#define PP_SSH                    24
#define PP_DNS                    25
#define PP_STREAM5                26
#define PP_DCERPC                 27

#define PRIORITY_FIRST 0x0
#define PRIORITY_NETWORK 0x10
#define PRIORITY_TRANSPORT 0x100
#define PRIORITY_SCANNER 0x110
#define PRIORITY_APPLICATION 0x200
#define PRIORITY_LAST 0xffff

#endif /* _PREPROC_IDS_H */

