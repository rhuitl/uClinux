#ifndef __HI_UI_SERVER_LOOKUP_H__
#define __HI_UI_SERVER_LOOKUP_H__

#include "hi_include.h"
#include "hi_ui_config.h"

int hi_ui_server_lookup_init(SERVER_LOOKUP **ServerLookup);
int hi_ui_server_lookup_add(SERVER_LOOKUP *ServerLookup, unsigned long IP,
                            HTTPINSPECT_CONF *ServerConf);

HTTPINSPECT_CONF *hi_ui_server_lookup_find(SERVER_LOOKUP *ServerLookup, 
                                            unsigned long Ip, int *iError);
HTTPINSPECT_CONF *hi_ui_server_lookup_first(SERVER_LOOKUP *ServerLookup,
                                            int *iError);
HTTPINSPECT_CONF *hi_ui_server_lookup_next(SERVER_LOOKUP *ServerLookup,
                                           int *iError);

#endif
