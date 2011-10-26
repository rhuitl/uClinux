#define WLAN_HOSTIF WLAN_PCMCIA
#include "hfa384x.c"
#include "prism2mgmt.c"
#include "prism2mib.c"
#include "prism2sta.c"

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,4,21) )
#if (WLAN_CPU_FAMILY == WLAN_Ix86)
#ifndef CONFIG_ISA
#warning "You may need to enable ISA support in your kernel."
#endif
#endif
#endif

static u_int	irq_mask = 0xdeb8;		/* Interrupt mask */
static int	irq_list[4] = { -1 };		/* Interrupt list */
static u_int	prism2_ignorevcc=0;		/* Boolean, if set, we
						 * ignore what the Vcc
						 * is set to and what the CIS
						 * says.
						 */
MODULE_PARM( irq_mask, "i");
MODULE_PARM( irq_list, "1-4i");
MODULE_PARM( prism2_ignorevcc, "i");

static dev_link_t	*dev_list = NULL;	/* head of instance list */


dev_link_t	*prism2sta_attach(void);
static void	prism2sta_detach(dev_link_t *link);
static void	prism2sta_config(dev_link_t *link);
static void	prism2sta_release(UINT32 arg);
static int 	prism2sta_event (event_t event, int priority, event_callback_args_t *args);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,68))
/*----------------------------------------------------------------
* cs_error
*
* Utility function to print card services error messages.
*
* Arguments:
*	handle	client handle identifying this CS client
*	func	CS function number that generated the error
*	ret	CS function return code
*
* Returns: 
*	nothing
* Side effects:
*
* Call context:
*	process thread
*	interrupt
----------------------------------------------------------------*/
static void cs_error(client_handle_t handle, int func, int ret)
{
#if CS_RELEASE_CODE < 0x2911
	CardServices(ReportError, dev_info, (void *)func, (void *)ret);
#else
	error_info_t err = { func, ret };
	pcmcia_report_error(handle, &err);
#endif
}
#else // kernel_version
static struct pcmcia_driver prism2_cs_driver = {
	.drv = { 
		.name = "prism2_cs",
	},
	.attach = prism2sta_attach,
	.detach = prism2sta_detach,
	.owner = THIS_MODULE,
};
#endif /* kernel_version */

/*----------------------------------------------------------------
* prism2sta_attach
*
* Half of the attach/detach pair.  Creates and registers a device
* instance with Card Services.  In this case, it also creates the
* wlandev structure and device private structure.  These are 
* linked to the device instance via its priv member.
*
* Arguments:
*	none
*
* Returns: 
*	A valid ptr to dev_link_t on success, NULL otherwise
*
* Side effects:
*	
*
* Call context:
*	process thread (insmod/init_module/register_pccard_driver)
----------------------------------------------------------------*/
dev_link_t *prism2sta_attach(void)
{
	client_reg_t		client_reg;
	int			result;
	dev_link_t		*link = NULL;
	wlandevice_t		*wlandev = NULL;
	hfa384x_t		*hw = NULL;

	DBFENTER;

	/* Alloc our structures */
	link =		kmalloc(sizeof(struct dev_link_t), GFP_KERNEL);

	if (!link || ((wlandev = create_wlan()) == NULL)) {
		WLAN_LOG_ERROR("%s: Memory allocation failure.\n", dev_info);
		result = -EIO;
		goto failed;
	}
	hw = wlandev->priv;

	/* Clear all the structs */
	memset(link, 0, sizeof(struct dev_link_t));

	if ( wlan_setup(wlandev) != 0 ) {
		WLAN_LOG_ERROR("%s: wlan_setup() failed.\n", dev_info);
		result = -EIO;
		goto failed;
	}

	/* Initialize the hw struct for now */
	hfa384x_create(hw, 0, 0, NULL);
	hw->wlandev = wlandev;

	/* Initialize the device private data stucture. */
	hw->cs_link = link;

	/* Initialize the PC card device object. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
	init_timer(&link->release);
	link->release.function = &prism2sta_release;
	link->release.data = (u_long)link;
#endif
	link->conf.IntType = INT_MEMORY_AND_IO;
	link->priv = wlandev;
#if CS_RELEASE_CODE > 0x2911
	link->irq.Instance = wlandev;
#endif

	/* Link in to the list of devices managed by this driver */
	link->next = dev_list;
	dev_list = link;	

	/* Register with Card Services */
	client_reg.dev_info = &dev_info;
	client_reg.Attributes = INFO_IO_CLIENT | INFO_CARD_SHARE;
	client_reg.EventMask =
		CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
		CS_EVENT_RESET_REQUEST |
		CS_EVENT_RESET_PHYSICAL | CS_EVENT_CARD_RESET |
		CS_EVENT_PM_SUSPEND | CS_EVENT_PM_RESUME;
	client_reg.event_handler = &prism2sta_event;
	client_reg.Version = 0x0210;
	client_reg.event_callback_args.client_data = link;

	result = pcmcia_register_client(&link->handle, &client_reg);
	if (result != 0) {
		cs_error(link->handle, RegisterClient, result);
		prism2sta_detach(link);
		return NULL;
	}

	goto done;

 failed:
	if (link)	kfree(link);
	if (wlandev)	kfree(wlandev);
	if (hw)		kfree(hw);
	link = NULL;

 done:
	DBFEXIT;
	return link;
}


/*----------------------------------------------------------------
* prism2sta_detach
*
* Remove one of the device instances managed by this driver.
*   Search the list for the given instance, 
*   check our flags for a waiting timer'd release call
*   call release
*   Deregister the instance with Card Services
*   (netdevice) unregister the network device.
*   unlink the instance from the list
*   free the link, priv, and priv->priv memory
* Note: the dev_list variable is a driver scoped static used to
*	maintain a list of device instances managed by this
*	driver.
*
* Arguments:
*	link	ptr to the instance to detach
*
* Returns: 
*	nothing
*
* Side effects:
*	the link structure is gone, the netdevice is gone
*
* Call context:
*	Might be interrupt, don't block.
----------------------------------------------------------------*/
void prism2sta_detach(dev_link_t *link)
{
	dev_link_t		**linkp;
	wlandevice_t		*wlandev;
	hfa384x_t		*hw;

	DBFENTER;

	/* Locate prev device structure */
	for (linkp = &dev_list; *linkp; linkp = &(*linkp)->next) {
		if (*linkp == link) break;
	}

	if (*linkp != NULL) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
		unsigned long	flags;
		/* Get rid of any timer'd release call */
		save_flags(flags);
		cli();
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
		if (link->state & DEV_RELEASE_PENDING) {
			del_timer_sync(&link->release);
			link->state &= ~DEV_RELEASE_PENDING;
		}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
		restore_flags(flags);
#endif

		/* If link says we're still config'd, call release */
		if (link->state & DEV_CONFIG) {
			prism2sta_release((u_long)link);
			if (link->state & DEV_STALE_CONFIG) {
				link->state |= DEV_STALE_LINK;
				return;
			}
		}
		
		/* Tell Card Services we're not around any more */
		if (link->handle) {
			pcmcia_deregister_client(link->handle);
		}	

		/* Unlink device structure, free bits */
		*linkp = link->next;
		if ( link->priv != NULL ) {
			wlandev = (wlandevice_t*)link->priv;
			p80211netdev_hwremoved(wlandev);
			if (link->dev != NULL) {
				unregister_wlandev(wlandev);
			}
			wlan_unsetup(wlandev);
			if (wlandev->priv) {
				hw = wlandev->priv;
				wlandev->priv = NULL;
				if (hw) {
					hfa384x_destroy(hw);
					kfree(hw);
				}
			}
			link->priv = NULL;
			kfree(wlandev);
		}
		kfree(link);
	}

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* prism2sta_config
*
* Half of the config/release pair.  Usually called in response to
* a card insertion event.  At this point, we _know_ there's some
* physical device present.  That means we can start poking around
* at the CIS and at any device specific config data we want.
*
* Note the gotos and the macros.  I recoded this once without
* them, and it got incredibly ugly.  It's actually simpler with
* them.
*
* Arguments:
*	link	the dev_link_t structure created in attach that 
*		represents this device instance.
*
* Returns: 
*	nothing
*
* Side effects:
*	Resources (irq, io, mem) are allocated
*	The pcmcia dev_link->node->name is set
*	(For netcards) The device structure is finished and,
*	  most importantly, registered.  This means that there
*	  is now a _named_ device that can be configured from
*	  userland.
*
* Call context:
*	May be called from a timer.  Don't block!
----------------------------------------------------------------*/
#define CS_CHECK(fn, ret) \
do { last_fn = (fn); if ((last_ret = (ret)) != 0) goto cs_failed; } while (0)

#define CFG_CHECK(fn, retf) \
do { int ret = (retf); \
if (ret != 0) { \
        WLAN_LOG_DEBUG(1, "CardServices(" #fn ") returned %d\n", ret); \
        cs_error(link->handle, fn, ret); \
        goto next_entry; \
} \
} while (0)

void prism2sta_config(dev_link_t *link)
{
	client_handle_t		handle;
	wlandevice_t		*wlandev;
	hfa384x_t               *hw;
	int			last_fn;
	int			last_ret;
	tuple_t			tuple;
	cisparse_t		parse;
	config_info_t		socketconf;
	UINT8			buf[64];
	int			i;
	int			minVcc = 0;
	int			maxVcc = 0;
	cistpl_cftable_entry_t	dflt = { 0 };

	DBFENTER;

	handle = link->handle;
	wlandev = (wlandevice_t*)link->priv;
	hw = wlandev->priv;

	/* Collect the config register info */
	tuple.DesiredTuple = CISTPL_CONFIG;
	tuple.Attributes = 0;
	tuple.TupleData = buf;
	tuple.TupleDataMax = sizeof(buf);
	tuple.TupleOffset = 0;
	CS_CHECK(GetFirstTuple, pcmcia_get_first_tuple(handle, &tuple));
	CS_CHECK(GetTupleData, pcmcia_get_tuple_data(handle, &tuple));
	CS_CHECK(ParseTuple, pcmcia_parse_tuple(handle, &tuple, &parse));

	link->conf.ConfigBase = parse.config.base;
	link->conf.Present = parse.config.rmask[0];
	
	/* Configure card */
	link->state |= DEV_CONFIG;

	/* Acquire the current socket config (need Vcc setting) */
	CS_CHECK(GetConfigurationInfo, pcmcia_get_configuration_info(handle, &socketconf));

	/* Loop through the config table entries until we find one that works */
	/* Assumes a complete and valid CIS */
	tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
	CS_CHECK(GetFirstTuple, pcmcia_get_first_tuple(handle, &tuple));
	while (1) {
		cistpl_cftable_entry_t *cfg = &(parse.cftable_entry);
		CFG_CHECK(GetTupleData, pcmcia_get_tuple_data(handle, &tuple));
		CFG_CHECK(ParseTuple, pcmcia_parse_tuple(handle, &tuple, &parse));

		if (cfg->index == 0) goto next_entry;
		link->conf.ConfigIndex = cfg->index;

		/* Lets print out the Vcc that the controller+pcmcia-cs set
		 * for us, cause that's what we're going to use.
		 */
		WLAN_LOG_DEBUG(1,"Initial Vcc=%d/10v\n", socketconf.Vcc);
		if (prism2_ignorevcc) {
			link->conf.Vcc = socketconf.Vcc;
			goto skipvcc;
		}

		/* Use power settings for Vcc and Vpp if present */
		/* Note that the CIS values need to be rescaled */
		if (cfg->vcc.present & (1<<CISTPL_POWER_VNOM)) {
			WLAN_LOG_DEBUG(1, "Vcc obtained from curtupl.VNOM\n");
			minVcc = maxVcc = 
				cfg->vcc.param[CISTPL_POWER_VNOM]/10000;
		} else if (dflt.vcc.present & (1<<CISTPL_POWER_VNOM)) {
			WLAN_LOG_DEBUG(1, "Vcc set from dflt.VNOM\n");
			minVcc = maxVcc = 
				dflt.vcc.param[CISTPL_POWER_VNOM]/10000;
		} else if ((cfg->vcc.present & (1<<CISTPL_POWER_VMAX)) &&
			   (cfg->vcc.present & (1<<CISTPL_POWER_VMIN)) ) {
			WLAN_LOG_DEBUG(1, "Vcc set from curtupl(VMIN,VMAX)\n");			minVcc = cfg->vcc.param[CISTPL_POWER_VMIN]/10000;
			maxVcc = cfg->vcc.param[CISTPL_POWER_VMAX]/10000;
		} else if ((dflt.vcc.present & (1<<CISTPL_POWER_VMAX)) &&
			   (dflt.vcc.present & (1<<CISTPL_POWER_VMIN)) ) {
			WLAN_LOG_DEBUG(1, "Vcc set from dflt(VMIN,VMAX)\n");
			minVcc = dflt.vcc.param[CISTPL_POWER_VMIN]/10000;
			maxVcc = dflt.vcc.param[CISTPL_POWER_VMAX]/10000;
		}

		if ( socketconf.Vcc >= minVcc && socketconf.Vcc <= maxVcc) {
			link->conf.Vcc = socketconf.Vcc;
		} else {
			/* [MSM]: Note that I've given up trying to change 
			 * the Vcc if a change is indicated.  It seems the
			 * system&socketcontroller&card vendors can't seem
			 * to get it right, so I'm tired of trying to hack
			 * my way around it.  pcmcia-cs does its best using 
			 * the voltage sense pins but sometimes the controller
			 * lies.  Then, even if we have a good read on the VS 
			 * pins, some system designs will silently ignore our
			 * requests to set the voltage.  Additionally, some 
			 * vendors have 3.3v indicated on their sense pins, 
			 * but 5v specified in the CIS or vice-versa.  I've
			 * had it.  My only recommendation is "let the buyer
			 * beware".  Your system might supply 5v to a 3v card
			 * (possibly causing damage) or a 3v capable system 
			 * might supply 5v to a 3v capable card (wasting 
			 * precious battery life).
			 * My only recommendation (if you care) is to get 
			 * yourself an extender card (I don't know where, I 
			 * have only one myself) and a meter and test it for
			 * yourself.
			 */
			goto next_entry;
		}
skipvcc:			
		WLAN_LOG_DEBUG(1, "link->conf.Vcc=%d\n", link->conf.Vcc);

		/* Do we need to allocate an interrupt? */
		/* HACK: due to a bad CIS....we ALWAYS need an interrupt */
		/* if (cfg->irq.IRQInfo1 || dflt.irq.IRQInfo1) */
			link->conf.Attributes |= CONF_ENABLE_IRQ;

		/* IO window settings */
		link->io.NumPorts1 = link->io.NumPorts2 = 0;
		if ((cfg->io.nwin > 0) || (dflt.io.nwin > 0)) {
			cistpl_io_t *io = (cfg->io.nwin) ? &cfg->io : &dflt.io;
			link->io.Attributes1 = IO_DATA_PATH_WIDTH_AUTO;
			if (!(io->flags & CISTPL_IO_8BIT))
				link->io.Attributes1 = IO_DATA_PATH_WIDTH_16;
			if (!(io->flags & CISTPL_IO_16BIT))
				link->io.Attributes1 = IO_DATA_PATH_WIDTH_8;
			link->io.BasePort1 = io->win[0].base;
			if  ( link->io.BasePort1 != 0 ) {
				WLAN_LOG_WARNING(
				"Brain damaged CIS: hard coded iobase="
				"0x%x, try letting pcmcia_cs decide...\n",
				link->io.BasePort1 );
				link->io.BasePort1 = 0;
			}
			link->io.NumPorts1 = io->win[0].len;
			if (io->nwin > 1) {
				link->io.Attributes2 = link->io.Attributes1;
				link->io.BasePort2 = io->win[1].base;
				link->io.NumPorts2 = io->win[1].len;
			}
		}

		/* This reserves IO space but doesn't actually enable it */
		CFG_CHECK(RequestIO, pcmcia_request_io(link->handle, &link->io));

		/* If we got this far, we're cool! */
		break;

next_entry:
		if (cfg->flags & CISTPL_CFTABLE_DEFAULT)
			dflt = *cfg;
		CS_CHECK(GetNextTuple,
                         pcmcia_get_next_tuple(handle, &tuple));
	}

	/* Allocate an interrupt line.  Note that this does not assign a */
	/* handler to the interrupt, unless the 'Handler' member of the */
	/* irq structure is initialized. */
	if (link->conf.Attributes & CONF_ENABLE_IRQ)
	{
		link->irq.Attributes = IRQ_TYPE_EXCLUSIVE | IRQ_HANDLE_PRESENT;
		link->irq.IRQInfo1 = IRQ_INFO2_VALID | IRQ_LEVEL_ID;
		if (irq_list[0] == -1)
			link->irq.IRQInfo2 = irq_mask;
		else
			for (i=0; i<4; i++)
				link->irq.IRQInfo2 |= 1 << irq_list[i];
		link->irq.Handler = hfa384x_interrupt;
		link->irq.Instance = wlandev;
		CS_CHECK(RequestIRQ, pcmcia_request_irq(link->handle, &link->irq));
	}

	/* This actually configures the PCMCIA socket -- setting up */
	/* the I/O windows and the interrupt mapping, and putting the */
	/* card and host interface into "Memory and IO" mode. */
	CS_CHECK(RequestConfiguration, pcmcia_request_configuration(link->handle, &link->conf));

	/* Fill the netdevice with this info */
	wlandev->netdev->irq = link->irq.AssignedIRQ;
	wlandev->netdev->base_addr = link->io.BasePort1;

	/* Report what we've done */
	WLAN_LOG_INFO("%s: index 0x%02x: Vcc %d.%d", 
		dev_info, link->conf.ConfigIndex, 
		link->conf.Vcc/10, link->conf.Vcc%10);
	if (link->conf.Vpp1)
		printk(", Vpp %d.%d", link->conf.Vpp1/10, link->conf.Vpp1%10);
	if (link->conf.Attributes & CONF_ENABLE_IRQ)
		printk(", irq %d", link->irq.AssignedIRQ);
	if (link->io.NumPorts1)
		printk(", io 0x%04x-0x%04x", link->io.BasePort1, link->io.BasePort1+link->io.NumPorts1-1);
	if (link->io.NumPorts2)
		printk(" & 0x%04x-0x%04x", link->io.BasePort2, link->io.BasePort2+link->io.NumPorts2-1);
	printk("\n");

	link->state &= ~DEV_CONFIG_PENDING;

	/* Let pcmcia know the device name */
	link->dev = &hw->node;

	/* Register the network device and get assigned a name */
	SET_MODULE_OWNER(wlandev->netdev);
	if (register_wlandev(wlandev) != 0) {
		WLAN_LOG_NOTICE("prism2sta_cs: register_wlandev() failed.\n");
		goto failed;
	}

	strcpy(hw->node.dev_name, wlandev->name);

	/* Any device custom config/query stuff should be done here */
	/* For a netdevice, we should at least grab the mac address */

	return;
cs_failed:
	cs_error(link->handle, last_fn, last_ret);
	WLAN_LOG_ERROR("NextTuple failure? It's probably a Vcc mismatch.\n");

failed:
	prism2sta_release((UINT32)link);
	return;
}



/*----------------------------------------------------------------
* prism2sta_release
*
* Half of the config/release pair.  Usually called in response to 
* a card ejection event.  Checks to make sure no higher layers
* are still (or think they are) using the card via the link->open
* field.  
*
* NOTE: Don't forget to increment the link->open variable in the 
*  device_open method, and decrement it in the device_close 
*  method.
*
* Arguments:
*	arg	a generic 32 bit variable.  It's the value that
*		we assigned to link->release.data in sta_attach().
*
* Returns: 
*	nothing
*
* Side effects:
*	All resources should be released after this function
*	executes and finds the device !open.
*
* Call context:
*	Possibly in a timer context.  Don't do anything that'll
*	block.
----------------------------------------------------------------*/
void prism2sta_release(UINT32 arg)
{
        dev_link_t	*link = (dev_link_t *)arg;

	DBFENTER;

	/* First thing we should do is get the MSD back to the
	 * HWPRESENT state.  I.e. everything quiescent.
	 */
	prism2sta_ifstate(link->priv, P80211ENUM_ifstate_disable);

        if (link->open) {
		/* TODO: I don't think we're even using this bit of code
		 * and I don't think it's hurting us at the moment.
		 */
                WLAN_LOG_DEBUG(1, 
			"prism2sta_cs: release postponed, '%s' still open\n",
			link->dev->dev_name);
                link->state |= DEV_STALE_CONFIG;
                return;
        }

        pcmcia_release_configuration(link->handle);
        pcmcia_release_io(link->handle, &link->io);
        pcmcia_release_irq(link->handle, &link->irq);

        link->state &= ~(DEV_CONFIG | DEV_RELEASE_PENDING);

	DBFEXIT;
}



/*----------------------------------------------------------------
* prism2sta_event
*
* Handler for card services events.
*
* Arguments:
*	event		The event code
*	priority	hi/low - REMOVAL is the only hi
*	args		ptr to card services struct containing info about
*			pcmcia status
*
* Returns: 
*	Zero on success, non-zero otherwise
*
* Side effects:
*	
*
* Call context:
*	Both interrupt and process thread, depends on the event.
----------------------------------------------------------------*/
static int 
prism2sta_event (
	event_t event, 
	int priority, 
	event_callback_args_t *args)
{
	int			result = 0;
	dev_link_t		*link = (dev_link_t *) args->client_data;
	wlandevice_t		*wlandev = (wlandevice_t*)link->priv;
	hfa384x_t		*hw = NULL;

	DBFENTER;

	if (wlandev) hw = wlandev->priv;

	switch (event)
	{
	case CS_EVENT_CARD_INSERTION:
		WLAN_LOG_DEBUG(5,"event is INSERTION\n");
		link->state |= DEV_PRESENT | DEV_CONFIG_PENDING;
		prism2sta_config(link);
		if (!(link->state & DEV_CONFIG)) {
			wlandev->netdev->irq = 0;
			WLAN_LOG_ERROR(
				"%s: Initialization failed!\n", dev_info);
			wlandev->msdstate = WLAN_MSD_HWFAIL;
			break;
		}

		/* Fill in the rest of the hw struct */
		hw->irq = wlandev->netdev->irq;
		hw->iobase = wlandev->netdev->base_addr;
		hw->membase = (UINT8*) link;

		if (prism2_doreset) {
			result = hfa384x_corereset(hw, 
					prism2_reset_holdtime, 
					prism2_reset_settletime, 0);
			if ( result ) {
				WLAN_LOG_ERROR(
					"corereset() failed, result=%d.\n", 
					result);
				wlandev->msdstate = WLAN_MSD_HWFAIL;
				break;
			}
		}

#if 0
		/*
		 * TODO: test_hostif() not implemented yet.
		 */
		result = hfa384x_test_hostif(hw);
		if (result) {
			WLAN_LOG_ERROR(
			"test_hostif() failed, result=%d.\n", result);
			wlandev->msdstate = WLAN_MSD_HWFAIL;
			break;
		}
#endif
		wlandev->msdstate = WLAN_MSD_HWPRESENT;
		break;

	case CS_EVENT_CARD_REMOVAL:
		WLAN_LOG_DEBUG(5,"event is REMOVAL\n");
		link->state &= ~DEV_PRESENT;

		if (wlandev) {
			p80211netdev_hwremoved(wlandev);
		}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
		if (link->state & DEV_CONFIG)
		{
			link->release.expires = jiffies + (HZ/20);
			add_timer(&link->release);
		}
#endif
		break;
	case CS_EVENT_RESET_REQUEST:
		WLAN_LOG_DEBUG(5,"event is RESET_REQUEST\n");
		WLAN_LOG_NOTICE(
			"prism2 card reset not supported "
			"due to post-reset user mode configuration "
			"requirements.\n");
		WLAN_LOG_NOTICE(
			"  From user mode, use "
			"'cardctl suspend;cardctl resume' "
			"instead.\n");
		break;
	case CS_EVENT_RESET_PHYSICAL:
	case CS_EVENT_CARD_RESET:
		WLAN_LOG_WARNING("Rx'd CS_EVENT_RESET_xxx, should not "
			"be possible since RESET_REQUEST was denied.\n");
		break;

	case CS_EVENT_PM_SUSPEND:
		WLAN_LOG_DEBUG(5,"event is SUSPEND\n");
		link->state |= DEV_SUSPEND;
		if (link->state & DEV_CONFIG)
		{
			prism2sta_ifstate(wlandev, P80211ENUM_ifstate_disable);
			pcmcia_release_configuration(link->handle);
		}
		break;

	case CS_EVENT_PM_RESUME:
		WLAN_LOG_DEBUG(5,"event is RESUME\n");
		link->state &= ~DEV_SUSPEND;
		if (link->state & DEV_CONFIG) {
			pcmcia_request_configuration(link->handle, &link->conf);
		}
		break;
	}

	DBFEXIT;
	return 0;  /* noone else does anthing with the return value */
}

#ifdef MODULE

static int __init prism2cs_init(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,68))
	servinfo_t	serv;
#endif

	DBFENTER;

        WLAN_LOG_NOTICE("%s Loaded\n", version);
        WLAN_LOG_NOTICE("dev_info is: %s\n", dev_info);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,68))
	pcmcia_get_card_services_info(&serv);
	if ( serv.Revision != CS_RELEASE_CODE )
	{
		printk(KERN_NOTICE"%s: CardServices release does not match!\n", dev_info);
		return -1;
	}

	/* This call will result in a call to prism2sta_attach */
	/*   and eventually prism2sta_detach */
	register_pccard_driver( &dev_info, &prism2sta_attach, &prism2sta_detach);
#else
	pcmcia_register_driver(&prism2_cs_driver);
#endif

	DBFEXIT;
	return 0;
}

static void __exit prism2cs_cleanup(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,68))
        dev_link_t *link = dev_list;
        dev_link_t *nlink;
        DBFENTER;

	for (link=dev_list; link != NULL; link = nlink) {
		nlink = link->next;
		if ( link->state & DEV_CONFIG ) {
			prism2sta_release((u_long)link);
		}
		prism2sta_detach(link); /* remember detach() frees link */
	}
	unregister_pccard_driver( &dev_info);
#else
	pcmcia_unregister_driver(&prism2_cs_driver);
#endif

        printk(KERN_NOTICE "%s Unloaded\n", version);

        DBFEXIT;
        return;
}

module_init(prism2cs_init);
module_exit(prism2cs_cleanup);

#endif // MODULE


int hfa384x_corereset(hfa384x_t *hw, int holdtime, int settletime, int genesis)
{
	int		result = 0;
	conf_reg_t	reg;
	UINT8		corsave;
	DBFENTER;

	WLAN_LOG_DEBUG(3, "Doing reset via CardServices().\n");

	/* Collect COR */
	reg.Function = 0; 
	reg.Action = CS_READ; 
	reg.Offset = CISREG_COR;
	result = pcmcia_access_configuration_register(
			((dev_link_t*)hw->membase)->handle,
			&reg);
	if (result != CS_SUCCESS ) {
		WLAN_LOG_ERROR(
			":0: AccessConfigurationRegister(CS_READ) failed,"
			"result=%d.\n", result); 
		result = -EIO;
	}
	corsave = reg.Value;

	/* Write reset bit (BIT7) */
	reg.Value |= BIT7;
	reg.Action = CS_WRITE;
	reg.Offset = CISREG_COR;
	result = pcmcia_access_configuration_register(
			((dev_link_t*)hw->membase)->handle,
			&reg);
	if (result != CS_SUCCESS ) {
		WLAN_LOG_ERROR(
			":1: AccessConfigurationRegister(CS_WRITE) failed,"
			"result=%d.\n", result); 
		result = -EIO;
	}

	/* Hold for holdtime */
	mdelay(holdtime);

	if (genesis) {
		reg.Value = genesis;
		reg.Action = CS_WRITE;
		reg.Offset = CISREG_CCSR;
		result = pcmcia_access_configuration_register(
			((dev_link_t*)hw->membase)->handle,
			&reg);
		if (result != CS_SUCCESS ) {
			WLAN_LOG_ERROR(
				":1: AccessConfigurationRegister(CS_WRITE) failed,"
				"result=%d.\n", result); 
			result = -EIO;
		}
	}

	/* Hold for holdtime */
	mdelay(holdtime);

	/* Clear reset bit */
	reg.Value &= ~BIT7;
	reg.Action = CS_WRITE;
	reg.Offset = CISREG_COR;
	result = pcmcia_access_configuration_register(
		((dev_link_t*)hw->membase)->handle,
		&reg);
	if (result != CS_SUCCESS ) {
		WLAN_LOG_ERROR(
			":2: AccessConfigurationRegister(CS_WRITE) failed,"
			"result=%d.\n", result); 
		result = -EIO;
		goto done;
	}

	/* Wait for settletime */
	mdelay(settletime);

	/* Set non-reset bits back what they were */
	reg.Value = corsave;
	reg.Action = CS_WRITE;
	reg.Offset = CISREG_COR;
	result = pcmcia_access_configuration_register(
		((dev_link_t*)hw->membase)->handle,
		&reg);
	if (result != CS_SUCCESS ) {
		WLAN_LOG_ERROR(
			":2: AccessConfigurationRegister(CS_WRITE) failed,"
			"result=%d.\n", result); 
		result = -EIO;
		goto done;
	}

done:
	DBFEXIT;
	return result;
}
