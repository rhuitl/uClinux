#ifndef _EVENT_WRAPPER_H
#define _EVENT_WRAPPER_H

#include "log.h"
#include "detect.h"
#include "decode.h"

u_int32_t GenerateSnortEvent(Packet *p,
                            u_int32_t gen_id,
                            u_int32_t sig_id,
                            u_int32_t sig_rev,
                            u_int32_t classification,
                            u_int32_t priority,
                            char *msg);

int LogTagData(Packet *p,
               u_int32_t gen_id,
               u_int32_t sig_id,
               u_int32_t sig_rev,
               u_int32_t classification,
               u_int32_t priority,
               u_int32_t event_ref,
               time_t ref_sec,
               char *msg);

#endif /* _EVENT_WRAPPER_H */
