#ifndef _PACKET_TIME_H
#define _PACKET_TIME_H

#include <time.h>

void packet_time_update(time_t cur);
time_t packet_timeofday(void);
time_t packet_first_time(void);

#endif /* _PACKET_TIME_H */
