#ifndef _TIMER_H_
#define _TIMER_H_

#include "linux_list.h"

struct alarm_list {
	struct list_head	head;
	unsigned long		expires;
	void			*data;
	void			(*function)(struct alarm_list *a, void *data);
};

#endif
