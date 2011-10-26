#ifndef __EVENT_QUEUE_H__
#define __EVENT_QUEUE_H__

#include "decode.h"

#define SNORT_EVENTQ_PRIORITY    1
#define SNORT_EVENTQ_CONTENT_LEN 2

typedef struct s_SNORT_EVENTQ_USER
{
    char rule_alert;
    void *pkt;

} SNORT_EVENTQ_USER;

typedef struct s_SNORT_EVENT_QUEUE
{
    int max_events;
    int log_events;
    int order;
    int process_all_events;

} SNORT_EVENT_QUEUE;

typedef struct _EventNode
{
    unsigned int gid;
    unsigned int sid;
    unsigned int rev;
    unsigned int classification;
    unsigned int priority;
    char        *msg;
    void        *rule_info;

} EventNode;

int  SnortEventqInit(void);
void SnortEventqReset(void);
int  SnortEventqLog(Packet *);
int  SnortEventqAdd(unsigned int gid,unsigned int sid,unsigned int rev, 
                    unsigned int classification,unsigned int pri,char *msg,
                    void *rule_info);

#endif
