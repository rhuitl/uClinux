#ifndef HOSTAP_COMPAT_H
#define HOSTAP_COMPAT_H

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,47))
#define NEW_MODULE_CODE
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,44))

#define HOSTAP_QUEUE struct tq_struct

#define PRISM2_SCHEDULE_TASK(q) \
MOD_INC_USE_COUNT; \
if (schedule_task((q)) == 0) \
	MOD_DEC_USE_COUNT;

static inline void flush_scheduled_work(void)
{
	flush_scheduled_tasks();
}

static inline void INIT_WORK(struct tq_struct *tq,
			     void (*routine)(void *), void *data)
{
	INIT_LIST_HEAD(&tq->list);
	tq->sync = 0;
	tq->routine = routine;
	tq->data = data;
}

#else /* kernel < 2.5.44 */

#define HOSTAP_QUEUE struct work_struct

#ifdef NEW_MODULE_CODE
#define PRISM2_SCHEDULE_TASK(q) schedule_work(q);
#else /* NEW_MODULE_CODE */
#define PRISM2_SCHEDULE_TASK(q) \
MOD_INC_USE_COUNT; \
if (schedule_work((q)) == 0) \
	MOD_DEC_USE_COUNT;
#endif /* NEW_MODULE_CODE */

#endif /* kernel < 2.5.44 */

#define HOSTAP_TASKLET struct tasklet_struct

#define HOSTAP_TASKLET_INIT(q, f, d) \
do { memset((q), 0, sizeof(*(q))); (q)->func = (f); (q)->data = (d); } \
while (0)


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,19))
#define yield() schedule()
#endif


/* Interrupt handler backwards compatibility for Linux < 2.5.69 */
#ifndef IRQ_NONE
#define IRQ_NONE
#define IRQ_HANDLED
#define IRQ_RETVAL(x)
typedef void irqreturn_t;
#endif

#ifndef SA_SHIRQ
#define SA_SHIRQ        IRQF_SHARED
#endif

#ifndef MODULE_LICENSE
#define MODULE_LICENSE(var)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,23))
#define free_netdev(dev) kfree(dev)
#endif


#ifdef __IN_PCMCIA_PACKAGE__
#undef pcmcia_access_configuration_register
#define pcmcia_access_configuration_register(handle, reg) \
	CardServices(AccessConfigurationRegister, handle, reg)

#undef pcmcia_register_client
#define pcmcia_register_client(handle, reg) \
	CardServices(RegisterClient, handle, reg)

#undef pcmcia_deregister_client
#define pcmcia_deregister_client(handle) \
	CardServices(DeregisterClient, handle)

#undef pcmcia_get_first_tuple
#define pcmcia_get_first_tuple(handle, tuple) \
	CardServices(GetFirstTuple, handle, tuple)

#undef pcmcia_get_next_tuple
#define pcmcia_get_next_tuple(handle, tuple) \
	CardServices(GetNextTuple, handle, tuple)

#undef pcmcia_get_tuple_data
#define pcmcia_get_tuple_data(handle, tuple) \
	CardServices(GetTupleData, handle, tuple)

#undef pcmcia_parse_tuple
#define pcmcia_parse_tuple(handle, tuple, parse) \
	CardServices(ParseTuple, handle, tuple, parse)

#undef pcmcia_get_configuration_info
#define pcmcia_get_configuration_info(handle, config) \
	CardServices(GetConfigurationInfo, handle, config)

#undef pcmcia_request_io
#define pcmcia_request_io(handle, req) \
	CardServices(RequestIO, handle, req)

#undef pcmcia_request_irq
#define pcmcia_request_irq(handle, req) \
	CardServices(RequestIRQ, handle, req)

#undef pcmcia_request_configuration
#define pcmcia_request_configuration(handle, req) \
	CardServices(RequestConfiguration, handle, req)

#undef pcmcia_release_configuration
#define pcmcia_release_configuration(handle) \
	CardServices(ReleaseConfiguration, handle)

#undef pcmcia_release_io
#define pcmcia_release_io(handle, req) \
	CardServices(ReleaseIO, handle, req)

#undef pcmcia_release_irq
#define pcmcia_release_irq(handle, req) \
	CardServices(ReleaseIRQ, handle, req)

#undef pcmcia_release_window
#define pcmcia_release_window(win) \
	CardServices(ReleaseWindow, win)

#undef pcmcia_get_card_services_info
#define pcmcia_get_card_services_info(info) \
	CardServices(GetCardServicesInfo, info)

#undef pcmcia_report_error
#define pcmcia_report_error(handle, err) \
	CardServices(ReportError, handle, err)
#endif /* __IN_PCMCIA_PACKAGE__ */

#endif /* HOSTAP_COMPAT_H */
