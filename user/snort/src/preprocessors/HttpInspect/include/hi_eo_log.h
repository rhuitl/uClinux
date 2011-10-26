#ifndef __HI_EO_LOG_H__
#define __HI_EO_LOG_H__

#include "hi_include.h"
#include "hi_si.h"
#include "hi_return_codes.h"

static INLINE int hi_eo_generate_event(HI_SESSION *Session, int iAlert)
{
    if(iAlert && !Session->server_conf->no_alerts)
    {
        return HI_BOOL_TRUE;
    }

    return HI_BOOL_FALSE;
}

int hi_eo_client_event_log(HI_SESSION *Session, int iEvent, void *data,
        void (*free_data)(void *));

int hi_eo_anom_server_event_log(HI_SESSION *Session, int iEvent, void *data,
        void (*free_data)(void *));

#endif
