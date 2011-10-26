#ifndef __SNORT_HTTPINSPECT_H__
#define __SNORT_HTTPINSPECT_H__


int HttpInspectSnortConf(HTTPINSPECT_GLOBAL_CONF *GlobalConf, char *args,
                         int iGlobal, char *ErrorString, int ErrStrLen);
int SnortHttpInspect(HTTPINSPECT_GLOBAL_CONF *GlobalConf, Packet *p);
void HttpInspectCheckConfig(void);

#endif
