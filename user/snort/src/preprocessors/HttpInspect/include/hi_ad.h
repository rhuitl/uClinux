#ifndef __HI_AD_H__
#define __HI_AD_H__

#include <sys/types.h>

#include "hi_include.h"
#include "hi_eo.h"


typedef struct s_HI_ANOM_SERVER
{
    HI_ANOM_SERVER_EVENTS event_list;

} HI_ANOM_SERVER;

int hi_server_anomaly_detection(void *S, u_char *data, int dsize);

#endif
