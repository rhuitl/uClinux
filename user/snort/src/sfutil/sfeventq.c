/**
**  @file       sfeventq.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This provides generic functions for queuing events and
**              inserting the events with a provided function.  All
**              memory management for events is provided here.
**
**  Copyright (C) 2004, Daniel Roelker and Sourcefire, Inc.
**
**  The sfeventq functions provide a generic way for handling events,
**  prioritizing those events, and acting on the highest ranked events
**  with a user function.
**
**  Example on using sfeventq:
**
**  1. Initialize event queue
**       sfeventq_init()
**
**  2. Add events to queue
**       sfeventq_event_alloc() allocates the memory for storing the event.
**       sfeventq_add() adds the event and prioritizes the event in the queue.
**       You should only allocate and add one event at a time.  Otherwise,
**       event_alloc() will return NULL on memory exhaustion.
**
**  3. Event actions
**       sfeventq_action() will call the provided function on the initialized
**       number of events to log.
*/

#include <stdlib.h>

typedef struct s_SF_EVENTQ_NODE
{
    void   *event;

    struct s_SF_EVENTQ_NODE *prev;
    struct s_SF_EVENTQ_NODE *next;

}  SF_EVENTQ_NODE;

typedef struct s_SF_EVENTQ
{
    /*
    **  Handles the actual ordering and memory
    **  of the event queue and it's nodes.
    */
    SF_EVENTQ_NODE *head;
    SF_EVENTQ_NODE *last;

    SF_EVENTQ_NODE *node_mem;
    char           *event_mem;

    /*
    **  The reserve event allows us to allocate one extra node
    **  and compare against the last event in the queue to determine
    **  if the incoming event is a higher priority than the last 
    **  event in the queue.
    */
    char           *reserve_event;
    
    /*
    **  Queue configuration
    */
    int max_nodes;
    int log_nodes;
    int event_size;

    /*
    **  This function orders the events as they
    **  arrive.
    */
    int (*sort)(void *event1, void *event2);

    /*
    **  This element tracks the current number of
    **  nodes in the event queue.
    */
    int cur_nodes;
    int cur_events;

}  SF_EVENTQ;

static SF_EVENTQ s_eventq;

/*
**  NAME
**    sfeventq_init::
*/
/**
**  Initialize the event queue.  Provide the max number of nodes that this
**  queue will support, the number of top nodes to log in the queue, the
**  size of the event structure that the user will fill in, and the function
**  to determine where to insert the incoming events in the queue.
**
**  @return integer
**
**  @retval -1 failure
**  @retval  0 success
*/
int sfeventq_init(int max_nodes, int log_nodes, int event_size, 
                  int (*sort)(void *, void *))
{
    if(max_nodes <= 0 || log_nodes <= 0 || event_size <= 0 ) /* || !sort) Jan06 -- not required */
        return -1;

    /*
    **  Initialize the memory for the nodes that we are going to use.
    */
    s_eventq.node_mem  = 
        (SF_EVENTQ_NODE *)malloc(sizeof(SF_EVENTQ_NODE)*max_nodes);
    if(!s_eventq.node_mem)
        return -1;

    s_eventq.event_mem = (char *)malloc(event_size*(max_nodes+1));
    if(!s_eventq.event_mem)
        return -1;

    s_eventq.max_nodes  = max_nodes;
    s_eventq.log_nodes  = log_nodes;
    s_eventq.event_size = event_size;
    s_eventq.sort       = sort;
    s_eventq.cur_nodes  = 0;
    s_eventq.cur_events = 0;
    s_eventq.reserve_event = 
        (void *)(&s_eventq.event_mem[max_nodes*s_eventq.event_size]);

    return 0;
}

/*
**  NAME
**    sfeventq_event_alloc::
*/
/**
**  Allocate the memory for an event to add to the event queue.  This
**  function is meant to be called first, the event structure filled in,
**  and then added to the queue.  While you can allocate several times before
**  adding to the queue, this is not recommended as you may get a NULL ptr
**  if you allocate more than the max node number.
**
**  @return  void *
**
**  @retval  NULL unable to allocate memory.
**  @retval !NULL ptr to memory.
*/
void *sfeventq_event_alloc(void)
{
    void *event;

    if(s_eventq.cur_events >= s_eventq.max_nodes)
    {
        if(!s_eventq.reserve_event)
            return NULL;
        
        event = (void *)s_eventq.reserve_event;
        s_eventq.reserve_event = NULL;

        return event;
    }

    event = 
        (void *)(&s_eventq.event_mem[s_eventq.cur_events*s_eventq.event_size]);

    s_eventq.cur_events++;


    return event;
}

/*
**  NAME
**    sfeventq_reset::
*/
/**
**  Resets the event queue.  We also set the reserve event back
**  to the last event in the queue.
**
**  @return void
*/
void sfeventq_reset(void)
{
    s_eventq.head       = NULL;
    s_eventq.cur_nodes  = 0;
    s_eventq.cur_events = 0;
    s_eventq.reserve_event = 
        (void *)(&s_eventq.event_mem[s_eventq.max_nodes*s_eventq.event_size]);

    return;
}

/*
**  NAME
**    get_eventq_node::
*/
/**
**  This function returns a ptr to the node to use.  We allocate the last
**  event node if we have exhausted the event queue.  Before we allocate
**  the last node, we determine if the incoming event has a higher
**  priority than the last node.  If it does, we allocate the node, otherwise
**  we drop it because it is lower priority.
**
**  If the last node is allocated, we have to point the reserve_event to
**  the allocated event memory, since the reserved_event memory was used
**  for the incoming event.
**
**  @return SF_EVENTQ_NODE *
**
**  @retval NULL resource exhaustion and event is lower priority than last node
**  @retval !NULL ptr to node memory.
*/
static SF_EVENTQ_NODE *get_eventq_node(void *event)
{
    SF_EVENTQ_NODE *node;

    if(s_eventq.cur_nodes >= s_eventq.max_nodes)
    {
        /*
        **  If this event does not have a higher priority than
        **  the last one, we don't won't it.
        */
        if (!s_eventq.sort)
        {
            return NULL;
        }

        if(!s_eventq.sort(event, s_eventq.last->event))
        {
            s_eventq.reserve_event = event;
            return NULL;
        }

        node = s_eventq.last;

        /*
        **  Set up new reserve event.
        */
        s_eventq.reserve_event = node->event;
        node->event = event;

        if(s_eventq.last->prev)
        {
            s_eventq.last       = s_eventq.last->prev;
            s_eventq.last->next = NULL;
        }

        /*
        **  Grab the last node for processing.
        */
        return node;
    }

    /*
    **  We grab the next node from the node memory.
    */
    return &s_eventq.node_mem[s_eventq.cur_nodes++];
}

/*
**  NAME
**    sfeventq_add:
*/
/**
**  Add this event to the queue using the supplied ordering
**  function.  If the queue is exhausted, then we compare the
**  event to be added with the last event, and decide whether
**  it is a higher priority than the last node.
**
**  @return integer
**
**  @retval -1 add event failed
**  @retval  0 add event succeeded
*/
int sfeventq_add(void *event)
{
    SF_EVENTQ_NODE *node;
    SF_EVENTQ_NODE *tmp;
    
    if(!event)
        return -1;

    /*
    **  If get_eventq_node() returns NULL, this means that
    **  we have exhausted the eventq and the incoming event
    **  is lower in priority then the last ranked event.
    **  So we just drop it.
    */
    node = get_eventq_node(event);
    if(!node)
        return 0;

    node->event = event;
    node->next  = NULL;
    node->prev  = NULL;

    /*
    **  This is the first node
    */
    if(s_eventq.cur_nodes == 1)
    {
        s_eventq.head = s_eventq.last = node;
        return 0;
    }

    /*
    **  Now we search for where to insert this node.
    */
    if( s_eventq.sort ) /* Not used --- Jan06 each action group is presorted in fpFinalSelect */
    {
        for(tmp = s_eventq.head; tmp; tmp = tmp->next)
        {
            if(s_eventq.sort(event, tmp->event))
            {
                /*
                **  Put node here.
                */
                if(tmp->prev)
                    tmp->prev->next = node;
                else
                    s_eventq.head   = node;

                node->prev = tmp->prev;
                node->next = tmp;

                tmp->prev  = node;

                return 0;
            }
        }
    }

    /*
    **  This means we are the last node.
    */
    node->prev          = s_eventq.last;

    s_eventq.last->next = node;
    s_eventq.last       = node;

    return 0;
}

/*
**  NAME
**    sfeventq_action::
*/
/** 
**  Call the supplied user action function on the highest priority
**  events.
**
**  @return integer
**
**  @retval -1 action function failed on an event
**  @retval  0 no events logged
**  @retval  1 events logged
*/
int sfeventq_action(int (*action_func)(void *, void *), void *user)
{
    SF_EVENTQ_NODE *node;
    int             logged = 0;

    if(!action_func)
        return -1;

    if(!(s_eventq.head))
        return 0;
    
    for(node = s_eventq.head; node; node = node->next)
    {
        if(logged >= s_eventq.log_nodes)
            return 1;

        if(action_func(node->event, user))
            return -1;

        logged++;
    }

    return 1;
}

//#define I_WANT_MY_MAIN
#ifdef  I_WANT_MY_MAIN

#include <stdio.h>
#include <time.h>

int mysort(void *event1, void *event2)
{
    int *e1;
    int *e2;

    if(!event1 || !event2)
        return 0;

    e1 = (int *)event1;
    e2 = (int *)event2;

    if(*e1 < *e2)
        return 1;

    return 0;
}

int myaction(void *event, void *user)
{
    int *e;

    if(!event)
        return 1;

    e = (int *)event;

    printf("-- EVENT: %d\n", *e);

    return 0;
}

int main(int argc, char **argv)
{
    int  max_events;
    int  log_events;
    int  add_events;
    int *event;
    int  iCtr;

    if(argc < 4)
    {
        printf("-- Not enough args\n");
        return 1;
    }

    max_events = atoi(argv[1]);
    if(max_events <= 0)
    {
        printf("-- max_events invalid.\n");
        return 1;
    }

    log_events = atoi(argv[2]);
    if(log_events <= 0)
    {
        printf("-- log_events invalid.\n");
        return 1;
    }

    add_events = atoi(argv[3]);
    if(add_events <= 0)
    {
        printf("-- add_events invalid.\n");
        return 1;
    }

    if(max_events < log_events)
    {
        printf("-- log_events greater than max_events\n");
        return 1;
    }

    srandom(time(NULL));

    sfeventq_init(max_events, log_events, sizeof(int), mysort);

    do
    {
        printf("-- Event Queue Test --\n\n");

        for(iCtr = 0; iCtr < add_events; iCtr++)
        {
            event  = (int *)sfeventq_event_alloc();
            if(!event)
            {
                printf("-- event allocation failed\n");
                return 1;
            }

            *event = (int)(random()%3);

            sfeventq_add(event);
            printf("-- added %d\n", *event);
        }

        printf("\n-- Logging\n\n");

        if(sfeventq_action(myaction, NULL))
        {
            printf("-- There was a problem.\n");
            return 1;
        }

        sfeventq_reset();

    } while(getc(stdin) < 14);
    
    return 0;
}
#endif
