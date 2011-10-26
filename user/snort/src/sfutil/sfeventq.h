#ifndef __SF_EVENTQ_H__
#define __SF_EVENTQ_H__

void *sfeventq_event_alloc(void);
void  sfeventq_reset(void);
int   sfeventq_add(void *event);
int   sfeventq_action(int (*action_func)(void *event, void *user), void *user);
int   sfeventq_init(int max_nodes, int log_nodes, int event_size, 
                    int (*sort)(void *, void *));

#endif
