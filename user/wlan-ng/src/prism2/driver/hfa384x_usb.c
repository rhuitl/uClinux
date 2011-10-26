/* src/prism2/driver/hfa384x_usb.c
*
* Functions that talk to the USB variantof the Intersil hfa384x MAC
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   The contents of this file are subject to the Mozilla Public
*   License Version 1.1 (the "License"); you may not use this file
*   except in compliance with the License. You may obtain a copy of
*   the License at http://www.mozilla.org/MPL/
*
*   Software distributed under the License is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   Alternatively, the contents of this file may be used under the
*   terms of the GNU Public License version 2 (the "GPL"), in which
*   case the provisions of the GPL are applicable instead of the
*   above.  If you wish to allow the use of your version of this file
*   only under the terms of the GPL and not to allow others to use
*   your version of this file under the MPL, indicate your decision
*   by deleting the provisions above and replace them with the notice
*   and other provisions required by the GPL.  If you do not delete
*   the provisions above, a recipient may use your version of this
*   file under either the MPL or the GPL.
*
* --------------------------------------------------------------------
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Portions of the development of this software were funded by 
* Intersil Corporation as part of PRISM(R) chipset product development.
*
* --------------------------------------------------------------------
*
* This file implements functions that correspond to the prism2/hfa384x
* 802.11 MAC hardware and firmware host interface.
*
* The functions can be considered to represent several levels of 
* abstraction.  The lowest level functions are simply C-callable wrappers
* around the register accesses.  The next higher level represents C-callable
* prism2 API functions that match the Intersil documentation as closely
* as is reasonable.  The next higher layer implements common sequences 
* of invokations of the API layer (e.g. write to bap, followed by cmd).
*
* Common sequences:
* hfa384x_drvr_xxx	Highest level abstractions provided by the 
*			hfa384x code.  They are driver defined wrappers 
*			for common sequences.  These functions generally
*			use the services of the lower levels.
*
* hfa384x_drvr_xxxconfig  An example of the drvr level abstraction. These
*			functions are wrappers for the RID get/set 
*			sequence. They 	call copy_[to|from]_bap() and 
*			cmd_access().	These functions operate on the 
*			RIDs and buffers without validation.  The caller
*			is responsible for that.
*
* API wrapper functions:
* hfa384x_cmd_xxx	functions that provide access to the f/w commands.  
*			The function arguments correspond to each command
*			argument, even command arguments that get packed
*			into single registers.  These functions _just_
*			issue the command by setting the cmd/parm regs
*			& reading the status/resp regs.  Additional
*			activities required to fully use a command
*			(read/write from/to bap, get/set int status etc.)
*			are implemented separately.  Think of these as
*			C-callable prism2 commands.
*
* Lowest Layer Functions:
* hfa384x_docmd_xxx	These functions implement the sequence required
*			to issue any prism2 command.  Primarily used by the
*			hfa384x_cmd_xxx functions.
*
* hfa384x_bap_xxx	BAP read/write access functions.
*			Note: we usually use BAP0 for non-interrupt context
*			 and BAP1 for interrupt context.
*
* hfa384x_dl_xxx	download related functions.
*                 	
* Driver State Issues:
* Note that there are two pairs of functions that manage the
* 'initialized' and 'running' states of the hw/MAC combo.  The four
* functions are create(), destroy(), start(), and stop().  create()
* sets up the data structures required to support the hfa384x_*
* functions and destroy() cleans them up.  The start() function gets
* the actual hardware running and enables the interrupts.  The stop()
* function shuts the hardware down.  The sequence should be:
* create()
* start()
*  .
*  .  Do interesting things w/ the hardware
*  .
* stop()
* destroy()
*
* Note that destroy() can be called without calling stop() first.
* --------------------------------------------------------------------
*/

/*================================================================*/
/* System Includes */
#define WLAN_DBVAR	prism2_debug

#include <wlan/version.h>

#include <linux/config.h>
#include <linux/version.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/wireless.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#include <asm/semaphore.h>
#include <asm/io.h>
#include <linux/delay.h>
#include <asm/byteorder.h>
#include <asm/bitops.h>
#include <linux/list.h>
#include <linux/usb.h>

#include <wlan/wlan_compat.h>

#if (WLAN_HOSTIF != WLAN_USB)
#error "This file is specific to USB"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,69)
static void
usb_init_urb(struct urb *urb)
{
	memset(urb, 0, sizeof(*urb));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) /* tune me! */
	urb->count = (atomic_t)ATOMIC_INIT(1);
#endif
	spin_lock_init(&urb->lock);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) /* tune me! */
#  define SUBMIT_URB(u,f)  usb_submit_urb(u,f)
#else
#  define SUBMIT_URB(u,f)  usb_submit_urb(u)
#endif

/*================================================================*/
/* Project Includes */

#include <wlan/p80211types.h>
#include <wlan/p80211hdr.h>
#include <wlan/p80211mgmt.h>
#include <wlan/p80211conv.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211netdev.h>
#include <wlan/p80211req.h>
#include <wlan/p80211metadef.h>
#include <wlan/p80211metastruct.h>
#include <prism2/hfa384x.h>
#include <prism2/prism2mgmt.h>

/*================================================================*/
/* Local Constants */

#define	DOWAIT		1
#define DOASYNC		0

/*================================================================*/
/* Local Macros */

#define ROUNDUP64(a) (((a)+63)&~63)

/*================================================================*/
/* Local Types */

/*================================================================*/
/* Local Static Definitions */
extern int prism2_debug;

/*================================================================*/
/* Local Function Declarations */

#ifdef DEBUG_USB
static void 
dbprint_urb(struct urb* urb);
#endif

static void
hfa384x_int_rxmonitor( 
	wlandevice_t *wlandev, 
	hfa384x_usb_rxfrm_t *rxfrm);

static void
hfa384x_usb_defer(void *hw);

static int
submit_rx_urb(hfa384x_t *hw, int flags);

static int
submit_tx_urb(hfa384x_t *hw, struct urb *tx_urb, int flags);

/*---------------------------------------------------*/
/* Callbacks */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static void 
hfa384x_usbout_callback(struct urb *urb);
static void
hfa384x_ctlxout_callback(struct urb *urb);
static void	
hfa384x_usbin_callback(struct urb *urb);
#else
static void 
hfa384x_usbout_callback(struct urb *urb, struct pt_regs *regs);
static void
hfa384x_ctlxout_callback(struct urb *urb, struct pt_regs *regs);
static void	
hfa384x_usbin_callback(struct urb *urb, struct pt_regs *regs);
#endif

static void
hfa384x_usbin_txcompl(wlandevice_t *wlandev, hfa384x_usbin_t *usbin);

static void
hfa384x_usbin_rx(wlandevice_t *wlandev, hfa384x_usbin_t *usbin);

static void
hfa384x_usbin_info(wlandevice_t *wlandev, hfa384x_usbin_t *usbin);

static void
hfa384x_usbout_tx(wlandevice_t *wlandev, hfa384x_usbout_t *usbout);

static void hfa384x_usbin_ctlx(wlandevice_t *wlandev, hfa384x_usbin_t *usbin, 
			       int urb_status);

/*---------------------------------------------------*/
/* Functions to support the prism2 usb command queue */
static int
hfa384x_usbctlxq_enqueue_run(
	hfa384x_usbctlxq_t *ctlxq,
	hfa384x_usbctlx_t *ctlx);

static void 
hfa384x_usbctlxq_run(hfa384x_usbctlxq_t *ctlxq);

static void 
hfa384x_usbctlx_reqtimerfn(unsigned long data);

static void 
hfa384x_usbctlx_resptimerfn(unsigned long data);

static void 
hfa384x_usbctlx_submit_wait(
	hfa384x_t		*hw, 
	hfa384x_usbctlx_t	*ctlx);

static int
hfa384x_usbctlx_submit_async(
	hfa384x_t		*hw, 
	hfa384x_usbctlx_t	*ctlx,
	ctlx_usercb_t		usercb,
	void			*usercb_data);

static void
hfa384x_usbctlx_init(hfa384x_usbctlx_t *ctlx, hfa384x_t *hw);

static void 
hfa384x_usbctlx_complete(hfa384x_usbctlx_t *ctlx);

static void
hfa384x_usbctlx_complete_async(deferred_data_t ctlx);

static int
hfa384x_usbctlx_cancel(hfa384x_usbctlx_t *ctlx);

static int
hfa384x_usbctlx_cancel_async(hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbcmd(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbrrid(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbwrid(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbrmem(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbwmem(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);


/*---------------------------------------------------*/
/* Low level req/resp CTLX formatters and submitters */
static int
hfa384x_docmd( 
	hfa384x_t *hw, 
	UINT	wait,
	hfa384x_metacmd_t *cmd,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_dorrid(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	rid,
	void	*riddata,
	UINT	riddatalen,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_dowrid(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	rid,
	void	*riddata,
	UINT	riddatalen,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_dormem(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	page,
	UINT16	offset,
	void	*data,
	UINT	len,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_dowmem(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	page,
	UINT16	offset,
	void	*data,
	UINT	len,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_isgood_pdrcode(UINT16 pdrcode);

/*================================================================*/
/* Function Definitions */

#ifdef DEBUG_USB
void
dbprint_urb(struct urb* urb)
{
	WLAN_LOG_DEBUG(3,"urb->pipe=0x%08x\n", urb->pipe);
	WLAN_LOG_DEBUG(3,"urb->status=0x%08x\n", urb->status);
	WLAN_LOG_DEBUG(3,"urb->transfer_flags=0x%08x\n", urb->transfer_flags);
	WLAN_LOG_DEBUG(3,"urb->transfer_buffer=0x%08x\n", (UINT)urb->transfer_buffer);
	WLAN_LOG_DEBUG(3,"urb->transfer_buffer_length=0x%08x\n", urb->transfer_buffer_length);
	WLAN_LOG_DEBUG(3,"urb->actual_length=0x%08x\n", urb->actual_length);
	WLAN_LOG_DEBUG(3,"urb->bandwidth=0x%08x\n", urb->bandwidth);
	WLAN_LOG_DEBUG(3,"urb->setup_packet(ctl)=0x%08x\n", (UINT)urb->setup_packet);
	WLAN_LOG_DEBUG(3,"urb->start_frame(iso/irq)=0x%08x\n", urb->start_frame);
	WLAN_LOG_DEBUG(3,"urb->interval(irq)=0x%08x\n", urb->interval);
	WLAN_LOG_DEBUG(3,"urb->error_count(iso)=0x%08x\n", urb->error_count);
	WLAN_LOG_DEBUG(3,"urb->timeout=0x%08x\n", urb->timeout);
	WLAN_LOG_DEBUG(3,"urb->context=0x%08x\n", (UINT)urb->context);
	WLAN_LOG_DEBUG(3,"urb->complete=0x%08x\n", (UINT)urb->complete);
}
#endif


/*----------------------------------------------------------------
* submit_rx_urb
*
* Listen for input data on the BULK-IN pipe. If the pipe has
* stalled then schedule it to be reset.
*
* Arguments:
*	hw		device struct
*	memflags	memory allocation flags
*
* Returns:
*	error code from submission
*
* Call context:
*	Any
----------------------------------------------------------------*/
static int
submit_rx_urb(hfa384x_t *hw, int memflags)
{
	unsigned long flags;
	hfa384x_usbin_t *usbin;
	int result;

	DBFENTER;
	
	usbin = kmalloc(sizeof(*usbin), memflags);
	if (usbin == NULL)
		return -ENOMEM;

	memset(usbin, 0, sizeof(*usbin));

	/* Post the IN urb */
	usb_fill_bulk_urb(&hw->rx_urb, hw->usb,
	              usb_rcvbulkpipe(hw->usb, hw->endp_in),
	              usbin, sizeof(*usbin),
	              hfa384x_usbin_callback, hw->wlandev);

	result = -ENOLINK;
	spin_lock_irqsave(&hw->ctlxq.lock, flags);
	if ( !hw->usb_removed && !test_bit(WORK_RX_HALT, &hw->work_flags)) {
		result = SUBMIT_URB(&hw->rx_urb, memflags);

		/* Check whether we need to reset the RX pipe */
		if (result == -EPIPE) {
			WLAN_LOG_WARNING("%s rx pipe stalled: requesting reset\n",
			                 hw->wlandev->netdev->name);
			set_bit(WORK_RX_HALT, &hw->work_flags);
			schedule_work(&hw->usb_work);
		}
	}
	spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

	/* Don't leak memory if anything should go wrong */
	if (result != 0)
		kfree(usbin);

	return result;
}

/*----------------------------------------------------------------
* submit_tx_urb
*
* Prepares and submits the URB of transmitted data. If the
* submission fails then it will schedule the output pipe to
* be reset.
*
* Arguments:
*	hw		device struct
*	tx_urb		URB of data for tranmission
*	memflags	memory allocation flags
*
* Returns:
*	error code from submission
*
* Call context:
*	Any
----------------------------------------------------------------*/
static int
submit_tx_urb(hfa384x_t *hw, struct urb *tx_urb, int memflags)
{
	struct net_device *netdev = hw->wlandev->netdev;
	unsigned long flags;
	int result;

	spin_lock_irqsave(&hw->ctlxq.lock, flags);

	result = -ENOLINK;
	if ( netif_running(netdev) ) {

		if ( !hw->usb_removed && !test_bit(WORK_TX_HALT, &hw->work_flags) ) {
			result = SUBMIT_URB(tx_urb, memflags);

			/* Test whether we need to reset the TX pipe */
			if (result == -EPIPE) {
				WLAN_LOG_WARNING("%s tx pipe stalled: requesting reset\n",
				                 netdev->name);
				set_bit(WORK_TX_HALT, &hw->work_flags);
				schedule_work(&hw->usb_work);
			}
			else if (result == 0) {
				netif_stop_queue(netdev);
			}
		}
	}

	spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

	return result;
}

/*----------------------------------------------------------------
* hfa394x_usb_defer
*
* There are some things that the USB stack cannot do while
* in interrupt context, so we arrange this function to run
* in process context.
*
* Arguments:
*	hw	device structure
*
* Returns:
*	nothing
*
* Call context:
*	process (by design)
----------------------------------------------------------------*/
static void
hfa384x_usb_defer(void *data)
{
	hfa384x_t *hw = data;
	struct net_device *netdev = hw->wlandev->netdev;
	unsigned long flags;

	/* Don't bother trying to reset anything if the plug
	 * has been pulled ...
	 */
	spin_lock_irqsave(&hw->ctlxq.lock, flags);
	if ( hw->usb_removed ) {
		spin_unlock_irqrestore(&hw->ctlxq.lock, flags);
		return;
	}
	spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

	/* Reception has stopped: try to reset the input pipe */
	if (test_bit(WORK_RX_HALT, &hw->work_flags)) {
		int ret;

		usb_unlink_urb(&hw->rx_urb);  /* Cannot be holding spinlock! */
		ret = usb_clear_halt(hw->usb,
		                     usb_rcvbulkpipe(hw->usb, hw->endp_in));
		if (ret != 0) {
			printk(KERN_ERR
			       "Failed to clear rx pipe for %s: err=%d\n",
			       netdev->name, ret);
		}
		else {
			printk(KERN_INFO "%s rx pipe reset complete.\n",
			                 netdev->name);
			clear_bit(WORK_RX_HALT, &hw->work_flags);
			submit_rx_urb(hw, GFP_KERNEL);
		}
	}

	/* Transmission has stopped: try to reset the output pipe */
	if (test_bit(WORK_TX_HALT, &hw->work_flags)) {
		int ret;

		usb_unlink_urb(&hw->tx_urb);
		ret = usb_clear_halt(hw->usb,
		                     usb_sndbulkpipe(hw->usb, hw->endp_out));
		if (ret != 0) {
			printk(KERN_ERR
			       "Failed to clear tx pipe for %s: err=%d\n",
			       netdev->name, ret);
		} else {
			printk(KERN_INFO "%s tx pipe reset complete.\n",
			                 netdev->name);
			p80211netdev_wake_queue(hw->wlandev);
			clear_bit(WORK_TX_HALT, &hw->work_flags);

			/* Stopping the BULK-OUT pipe also blocked
			 * us from sending any more CTLX URBs, so
			 * we need to re-run our queue ...
			 */
			hfa384x_usbctlxq_run(&hw->ctlxq);
		}
	}
}


/*----------------------------------------------------------------
* hfa384x_create
*
* Sets up the hfa384x_t data structure for use.  Note this
* does _not_ intialize the actual hardware, just the data structures
* we use to keep track of its state.
*
* Arguments:
*	hw		device structure
*	irq		device irq number
*	iobase		i/o base address for register access
*	membase		memory base address for register access
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
void
hfa384x_create( hfa384x_t *hw, struct usb_device *usb)
{
	DBFENTER;

	memset(hw, 0, sizeof(hfa384x_t));
	hw->usb = usb;
	hw->endp_in = -1;
	hw->endp_out = -1;

	/* Set up the waitq */
	init_waitqueue_head(&hw->cmdq);

	/* Initialize the command queue */
	spin_lock_init(&hw->ctlxq.lock);
	INIT_LIST_HEAD(&hw->ctlxq.pending);
	INIT_LIST_HEAD(&hw->ctlxq.active);
	INIT_LIST_HEAD(&hw->ctlxq.finished);

	/* Initialize the authentication queue */
	skb_queue_head_init(&hw->authq);

	INIT_WORK(&hw->link_bh, prism2sta_processing_defer, hw);
	INIT_WORK(&hw->usb_work, hfa384x_usb_defer, hw);

	usb_init_urb(&hw->rx_urb);
	usb_init_urb(&hw->tx_urb);

/* We need to make sure everything is set up to do USB transfers after this
 * function is complete.
 * Normally, Initialize will be called after this is set up.
 */
	hw->link_status = HFA384x_LINK_NOTCONNECTED;
	hw->state = HFA384x_STATE_INIT;

	DBFEXIT;
}

/*----------------------------------------------------------------
* hfa384x_destroy
*
* Partner to hfa384x_create().  This function cleans up the hw
* structure so that it can be freed by the caller using a simple
* kfree.  Currently, this function is just a placeholder.  If, at some
* point in the future, an hw in the 'shutdown' state requires a 'deep'
* kfree, this is where it should be done.  Note that if this function
* is called on a _running_ hw structure, the drvr_stop() function is
* called.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	nothing, this function is not allowed to fail.
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
void
hfa384x_destroy( hfa384x_t *hw)
{
	struct sk_buff *skb;

	DBFENTER;

	if ( hw->state == HFA384x_STATE_RUNNING ) {
		hfa384x_drvr_stop(hw);
	}
	hw->state = HFA384x_STATE_PREINIT;		

	if (hw->scanresults) {
		kfree(hw->scanresults);
		hw->scanresults = NULL;
	}

	/* Now to clean out the auth queue */
        while ( (skb = skb_dequeue(&hw->authq)) ) {
                dev_kfree_skb(skb);
        }		

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_cbcmd
*
* Ctlx_complete handler for async CMD type control exchanges.
* mark the hw struct as such.
*
* Note: If the handling is changed here, it should probably be 
*       changed in docmd as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbcmd(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	DBFENTER;

	if ( ctlx->usercb != NULL ) {
		hfa384x_async_cmdresult_t	cmdresult;
		CTLX_STATE			result;

		memset(&cmdresult, 0, sizeof(cmdresult));
		result = ctlx->state;
		if (result == CTLX_COMPLETE) {
			cmdresult.status = 
				hfa384x2host_16(ctlx->inbuf.cmdresp.status);
			cmdresult.resp0 = 
				hfa384x2host_16(ctlx->inbuf.cmdresp.resp0);
			cmdresult.resp1 = 
				hfa384x2host_16(ctlx->inbuf.cmdresp.resp1);
			cmdresult.resp2 = 
				hfa384x2host_16(ctlx->inbuf.cmdresp.resp2);
		}
	
		ctlx->usercb(hw, result, &cmdresult, ctlx->usercb_data);
	}

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_cbrrid
*
* CTLX completion handler for async RRID type control exchanges.
* 
* Note: If the handling is changed here, it should probably be 
*       changed in dorrid as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbrrid(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	DBFENTER;

	if ( ctlx->usercb != NULL ) {
		hfa384x_async_rridresult_t	rridresult;
		CTLX_STATE			result;

		memset(&rridresult, 0, sizeof(rridresult));
		result = ctlx->state;
	
		if (result == CTLX_COMPLETE) {
			rridresult.rid = 
				hfa384x2host_16(ctlx->inbuf.rridresp.rid);
			rridresult.riddata = ctlx->inbuf.rridresp.data;
			rridresult.riddata_len = 
			((hfa384x2host_16(ctlx->inbuf.rridresp.frmlen)-1)*2);
		}

		ctlx->usercb(hw, result, &rridresult, ctlx->usercb_data);
	}

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_cbwrid
*
* CTLX completion handler for async WRID type control exchanges.
*
* Note: If the handling is changed here, it should probably be 
*       changed in dowrid as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbwrid(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	DBFENTER;

	if ( ctlx->usercb != NULL ) {
		hfa384x_async_wridresult_t	wridresult;
		CTLX_STATE			result;

		memset(&wridresult, 0, sizeof(wridresult));
		result = ctlx->state;
		if (result == CTLX_COMPLETE) {
			wridresult.status = 
				hfa384x2host_16(ctlx->inbuf.wridresp.status);
			wridresult.resp0 = 
				hfa384x2host_16(ctlx->inbuf.wridresp.resp0);
			wridresult.resp1 = 
				hfa384x2host_16(ctlx->inbuf.wridresp.resp1);
			wridresult.resp2 = 
				hfa384x2host_16(ctlx->inbuf.wridresp.resp2);
		}

		ctlx->usercb(hw, result, &wridresult, ctlx->usercb_data);
	}

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_cbrmem
*
* CTLX completion handler for async RMEM type control exchanges.
*
* Note: If the handling is changed here, it should probably be 
*       changed in dormem as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbrmem(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	DBFENTER;

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_cbwmem
*
* CTLX completion handler for async WMEM type control exchanges.
*
* Note: If the handling is changed here, it should probably be 
*       changed in dowmem as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbwmem(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	DBFENTER;

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_cmd_initialize
*
* Issues the initialize command and sets the hw->state based
* on the result.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
int
hfa384x_cmd_initialize(hfa384x_t *hw)
{
	int	result = 0;
	int	i;
	hfa384x_metacmd_t cmd;

	DBFENTER;


	cmd.cmd = HFA384x_CMDCODE_INIT;
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);


	WLAN_LOG_DEBUG(3,"cmdresp.init: "
		"status=0x%04x, resp0=0x%04x, "
		"resp1=0x%04x, resp2=0x%04x\n",
		cmd.status, cmd.resp0, cmd.resp1, cmd.resp2);
	if ( result == 0 ) {
		for ( i = 0; i < HFA384x_NUMPORTS_MAX; i++) {
			hw->port_enabled[i] = 0;
		}
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_disable
*
* Issues the disable command to stop communications on one of 
* the MACs 'ports'.
*
* Arguments:
*	hw		device structure
*	macport		MAC port number (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_disable(hfa384x_t *hw, UINT16 macport)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_DISABLE) |
		  HFA384x_CMD_MACPORT_SET(macport);
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_enable
*
* Issues the enable command to enable communications on one of 
* the MACs 'ports'.
*
* Arguments:
*	hw		device structure
*	macport		MAC port number
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_enable(hfa384x_t *hw, UINT16 macport)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_ENABLE) |
		  HFA384x_CMD_MACPORT_SET(macport);
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_notify
*
* Sends an info frame to the firmware to alter the behavior
* of the f/w asynch processes.  Can only be called when the MAC
* is in the enabled state.
*
* Arguments:
*	hw		device structure
*	reclaim		[0|1] indicates whether the given FID will
*			be handed back (via Alloc event) for reuse.
*			(host order)
*	fid		FID of buffer containing the frame that was
*			previously copied to MAC memory via the bap.
*			(host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*	hw->resp0 will contain the FID being used by async notify
*	process.  If reclaim==0, resp0 will be the same as the fid
*	argument.  If reclaim==1, resp0 will be the different.
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_notify(hfa384x_t *hw, UINT16 reclaim, UINT16 fid, 
		       void *buf, UINT16 len)
{
#if 0
	int	result = 0;
	UINT16	cmd;
	DBFENTER;
	cmd =	HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_NOTIFY) |
		HFA384x_CMD_RECL_SET(reclaim);
	result = hfa384x_docmd_wait(hw, cmd, fid, 0, 0);
	
	DBFEXIT;
	return result;
#endif
return 0;
}


/*----------------------------------------------------------------
* hfa384x_cmd_inquiry
*
* Requests an info frame from the firmware.  The info frame will
* be delivered asynchronously via the Info event.
*
* Arguments:
*	hw		device structure
*	fid		FID of the info frame requested. (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_inquiry(hfa384x_t *hw, UINT16 fid)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_INQ);
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);
	
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_monitor
*
* Enables the 'monitor mode' of the MAC.  Here's the description of
* monitor mode that I've received thus far:
*
*  "The "monitor mode" of operation is that the MAC passes all 
*  frames for which the PLCP checks are correct. All received 
*  MPDUs are passed to the host with MAC Port = 7, with a  
*  receive status of good, FCS error, or undecryptable. Passing 
*  certain MPDUs is a violation of the 802.11 standard, but useful 
*  for a debugging tool."  Normal communication is not possible
*  while monitor mode is enabled.
*
* Arguments:
*	hw		device structure
*	enable		a code (0x0b|0x0f) that enables/disables
*			monitor mode. (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_monitor(hfa384x_t *hw, UINT16 enable)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_MONITOR) |
		HFA384x_CMD_AINFO_SET(enable);
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);
	
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_download
*
* Sets the controls for the MAC controller code/data download
* process.  The arguments set the mode and address associated 
* with a download.  Note that the aux registers should be enabled
* prior to setting one of the download enable modes.
*
* Arguments:
*	hw		device structure
*	mode		0 - Disable programming and begin code exec
*			1 - Enable volatile mem programming
*			2 - Enable non-volatile mem programming
*			3 - Program non-volatile section from NV download
*			    buffer. 
*			(host order)
*	lowaddr		
*	highaddr	For mode 1, sets the high & low order bits of 
*			the "destination address".  This address will be
*			the execution start address when download is
*			subsequently disabled.
*			For mode 2, sets the high & low order bits of 
*			the destination in NV ram.
*			For modes 0 & 3, should be zero. (host order)
*			NOTE: these are CMD format.
*	codelen		Length of the data to write in mode 2, 
*			zero otherwise. (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_download(hfa384x_t *hw, UINT16 mode, UINT16 lowaddr, 
				UINT16 highaddr, UINT16 codelen)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;
	WLAN_LOG_DEBUG(5,
		"mode=%d, lowaddr=0x%04x, highaddr=0x%04x, codelen=%d\n",
		mode, lowaddr, highaddr, codelen);

	cmd.cmd = (HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_DOWNLD) |
		   HFA384x_CMD_PROGMODE_SET(mode));

	cmd.parm0 = lowaddr;
	cmd.parm1 = highaddr;
	cmd.parm2 = codelen;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_copy_from_aux
*
* Copies a collection of bytes from the controller memory.  The
* Auxiliary port MUST be enabled prior to calling this function.
* We _might_ be in a download state.
*
* Arguments:
*	hw		device structure
*	cardaddr	address in hfa384x data space to read
*	auxctl		address space select
*	buf		ptr to destination host buffer
*	len		length of data to transfer (in bytes)
*
* Returns: 
*	nothing
*
* Side effects:
*	buf contains the data copied
*
* Call context:
*	process
*	interrupt
----------------------------------------------------------------*/
void 
hfa384x_copy_from_aux(
	hfa384x_t *hw, UINT32 cardaddr, UINT32 auxctl, void *buf, UINT len)
{
	DBFENTER;
	WLAN_LOG_ERROR("not used in USB.\n");
	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_copy_to_aux
*
* Copies a collection of bytes to the controller memory.  The
* Auxiliary port MUST be enabled prior to calling this function.
* We _might_ be in a download state.
*
* Arguments:
*	hw		device structure
*	cardaddr	address in hfa384x data space to read
*	auxctl		address space select
*	buf		ptr to destination host buffer
*	len		length of data to transfer (in bytes)
*
* Returns: 
*	nothing
*
* Side effects:
*	Controller memory now contains a copy of buf
*
* Call context:
*	process
*	interrupt
----------------------------------------------------------------*/
void 
hfa384x_copy_to_aux(
	hfa384x_t *hw, UINT32 cardaddr, UINT32 auxctl, void *buf, UINT len)
{
	DBFENTER;
	WLAN_LOG_ERROR("not used in USB.\n");
	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_corereset
*
* Perform a reset of the hfa38xx MAC core.  We assume that the hw 
* structure is in its "created" state.  That is, it is initialized
* with proper values.  Note that if a reset is done after the 
* device has been active for awhile, the caller might have to clean 
* up some leftover cruft in the hw structure.
*
* Arguments:
*	hw		device structure
*	holdtime	how long (in ms) to hold the reset
*	settletime	how long (in ms) to wait after releasing
*			the reset
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_corereset(hfa384x_t *hw, int holdtime, int settletime, int genesis)
{

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
	struct usb_device	*parent = hw->usb->parent;
	int			i;
	int			port = -1;
#endif

	int 			result = 0;


#define P2_USB_RT_PORT		(USB_TYPE_CLASS | USB_RECIP_OTHER)
#define P2_USB_FEAT_RESET	4
#define P2_USB_FEAT_C_RESET	20

	DBFENTER;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
	/* Find the hub port */
	for ( i = 0; i < parent->maxchild; i++) {
		if (parent->children[i] == hw->usb) {
			port = i;
			break;
		}
	}
	if (port < 0) return -ENOENT;

	/* Set and clear the reset */
	usb_control_msg(parent, usb_sndctrlpipe(parent, 0), 
		USB_REQ_SET_FEATURE, P2_USB_RT_PORT, P2_USB_FEAT_RESET, 
		port+1, NULL, 0, 1*HZ);
	wait_ms(holdtime);
	usb_control_msg(parent, usb_sndctrlpipe(parent, 0), 
		USB_REQ_CLEAR_FEATURE, P2_USB_RT_PORT, P2_USB_FEAT_C_RESET, 
		port+1, NULL, 0, 1*HZ);
	wait_ms(settletime);

	/* Set the device address */
	result=usb_set_address(hw->usb);
	if (result < 0) {
		WLAN_LOG_ERROR("reset_usbdev: Dev not accepting address, "
			"result=%d\n", result);
		clear_bit(hw->usb->devnum, &hw->usb->bus->devmap.devicemap);
		hw->usb->devnum = -1;
		goto done;
	}
	/* Let the address settle */
	wait_ms(20);

	/* Assume we're reusing the original descriptor data */
	
	/* Set the configuration. */
	WLAN_LOG_DEBUG(3, "Setting Configuration %d\n", 
		hw->usb->config[0].bConfigurationValue);
	result=usb_set_configuration(hw->usb, hw->usb->config[0].bConfigurationValue);
	if ( result ) {
		WLAN_LOG_ERROR("usb_set_configuration() failed, result=%d.\n",
				result);
		goto done;
	}	
	/* Let the configuration settle */
	wait_ms(20);

 done:	
#else
	WLAN_LOG_WARNING("hfa384x_corereset not supported on USB on 2.5/2.6 kernels.\n");
#endif

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_docmd
*
* Constructs a command CTLX and submits it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbcmd() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*       cmd             cmd structure.  Includes all arguments and result
*                       data points.  All in host order. in host order

*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*			for wait==1 calls
*
* Returns: 
*	0		success
*	-EIO		CTLX failure
*	-ERESTARTSYS	Awakened on signal
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
*
* Call context:
*	process 
----------------------------------------------------------------*/
static int 
hfa384x_docmd( 
	hfa384x_t *hw, 
	UINT	wait,
	hfa384x_metacmd_t *cmd,
	ctlx_usercb_t	usercb,
	void	*usercb_data)
{
	int			result;
	hfa384x_usbctlx_t	*ctlx;
	
	DBFENTER;
	ctlx = kmalloc(sizeof(*ctlx), in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	hfa384x_usbctlx_init(ctlx, hw);

	/* Initialize the command */
	ctlx->outbuf.cmdreq.type = 	host2hfa384x_16(HFA384x_USB_CMDREQ);
	ctlx->outbuf.cmdreq.cmd =	host2hfa384x_16(cmd->cmd);
	ctlx->outbuf.cmdreq.parm0 =	host2hfa384x_16(cmd->parm0);
	ctlx->outbuf.cmdreq.parm1 =	host2hfa384x_16(cmd->parm1);
	ctlx->outbuf.cmdreq.parm2 =	host2hfa384x_16(cmd->parm2);

	WLAN_LOG_DEBUG(4, "cmdreq: cmd=0x%04x "
		"parm0=0x%04x parm1=0x%04x parm2=0x%04x\n",
		cmd->cmd,
		cmd->parm0,
		cmd->parm1,
		cmd->parm2);

	/* Fill the out packet */
	usb_fill_bulk_urb( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), ROUNDUP64(sizeof(ctlx->outbuf.cmdreq)),
		hfa384x_ctlxout_callback, ctlx);
	ctlx->outurb.transfer_flags |= USB_QUEUE_BULK;

	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else if ( hfa384x_usbctlx_submit_async(
	                               hw, ctlx, usercb, usercb_data) == 0 ) {
		result = 0;
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case CTLX_COMPLETE:
		result = hfa384x2host_16(ctlx->inbuf.cmdresp.status);
		result &= HFA384x_STATUS_RESULT;

		cmd->status = hfa384x2host_16(ctlx->inbuf.cmdresp.status);
		cmd->resp0 = hfa384x2host_16(ctlx->inbuf.cmdresp.resp0);
		cmd->resp1 = hfa384x2host_16(ctlx->inbuf.cmdresp.resp1);
		cmd->resp2 = hfa384x2host_16(ctlx->inbuf.cmdresp.resp2);
		WLAN_LOG_DEBUG(4, "cmdresp:status=0x%04x "
			"resp0=0x%04x resp1=0x%04x resp2=0x%04x\n",
			cmd->status,
			cmd->resp0,
			cmd->resp1,
			cmd->resp2);
		break;
	case CTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case CTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case CTLX_REQ_FAILED:
		WLAN_LOG_WARNING("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case CTLX_START:
		result = -EIO;
		break;
	default:
		result = -ERESTARTSYS;
		break;
	} /* switch */

	complete(&ctlx->done);
	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_dorrid
*
* Constructs a read rid CTLX and issues it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbrrid() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*	rid		Read RID number (host order)
*	riddata		Caller supplied buffer that MAC formatted RID.data 
*			record will be written to for wait==1 calls. Should
*			be NULL for wait==0 calls.
*	riddatalen	Buffer length for wait==1 calls. Zero for wait==0 calls.
*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*			for wait==1 calls
*
* Returns: 
*	0		success
*	-EIO		CTLX failure
*	-ERESTARTSYS	Awakened on signal
*	-ENODATA	riddatalen != macdatalen
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
* Call context:
*	interrupt (wait==0)
*	process (wait==0 || wait==1)
----------------------------------------------------------------*/
static int
hfa384x_dorrid(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	rid,
	void	*riddata,
	UINT	riddatalen,
	ctlx_usercb_t usercb,
	void	*usercb_data)
{
	int			result;
	hfa384x_usbctlx_t	*ctlx;
	UINT			maclen;
	
	DBFENTER;
	ctlx = kmalloc(sizeof(*ctlx), in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	hfa384x_usbctlx_init(ctlx, hw);

	/* Initialize the command */
	ctlx->outbuf.rridreq.type =   host2hfa384x_16(HFA384x_USB_RRIDREQ);
	ctlx->outbuf.rridreq.frmlen = 
		host2hfa384x_16(sizeof(ctlx->outbuf.rridreq.rid));
	ctlx->outbuf.rridreq.rid =    host2hfa384x_16(rid);

	/* Fill the out packet */
	usb_fill_bulk_urb( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), ROUNDUP64(sizeof(ctlx->outbuf.rridreq)),
		hfa384x_ctlxout_callback, ctlx);
	ctlx->outurb.transfer_flags |= USB_QUEUE_BULK;

	/* Submit the CTLX */
	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else if ( hfa384x_usbctlx_submit_async(
	                              hw, ctlx, usercb, usercb_data) == 0 ) {
		result = 0;
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case CTLX_COMPLETE:
		/* The results are in ctlx->outbuf */
		/* Validate the length, note body len calculation in bytes */
		maclen = ((hfa384x2host_16(ctlx->inbuf.rridresp.frmlen)-1)*2);
		if ( maclen != riddatalen ) {  
			WLAN_LOG_WARNING(
			"RID len mismatch, rid=0x%04x hlen=%d fwlen=%d\n",
			rid, riddatalen, maclen);
			result = -ENODATA;
			break;
		}
		memcpy( riddata, ctlx->inbuf.rridresp.data, riddatalen);
		result = 0;
		break;

	case CTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case CTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case CTLX_REQ_FAILED:
		WLAN_LOG_WARNING("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case CTLX_START:
		result = -EIO;
		break;
	default:
		result = -ERESTARTSYS;
		break;
	} /* switch */

	complete(&ctlx->done);
	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_dowrid
*
* Constructs a write rid CTLX and issues it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbwrid() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*	rid		RID code
*	riddata		Data portion of RID formatted for MAC
*	riddatalen	Length of the data portion in bytes
*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*
* Returns: 
*	0		success
*	-ETIMEDOUT	timed out waiting for register ready or
*			command completion
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
* Call context:
*	interrupt (wait==0)
*	process (wait==0 || wait==1)
----------------------------------------------------------------*/
int
hfa384x_dowrid(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	rid,
	void	*riddata,
	UINT	riddatalen,
	ctlx_usercb_t usercb,
	void	*usercb_data)
{
	int			result;
	hfa384x_usbctlx_t	*ctlx;
	
	DBFENTER;
	ctlx = kmalloc(sizeof(*ctlx), in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	hfa384x_usbctlx_init(ctlx, hw);

	/* Initialize the command */
	ctlx->outbuf.wridreq.type =   host2hfa384x_16(HFA384x_USB_WRIDREQ);
	ctlx->outbuf.wridreq.frmlen = host2hfa384x_16(
					(sizeof(ctlx->outbuf.rridreq.rid) + 
					riddatalen + 1) / 2);
	ctlx->outbuf.wridreq.rid =    host2hfa384x_16(rid);
	memcpy(ctlx->outbuf.wridreq.data, riddata, riddatalen);

	/* Fill the out packet */
	usb_fill_bulk_urb( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), 
		ROUNDUP64( sizeof(ctlx->outbuf.wridreq.type) +
			sizeof(ctlx->outbuf.wridreq.frmlen) +
			sizeof(ctlx->outbuf.wridreq.rid) +
			riddatalen),
		hfa384x_ctlxout_callback, 
		ctlx);
	ctlx->outurb.transfer_flags |= USB_QUEUE_BULK;

	/* Submit the CTLX */
	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else if ( hfa384x_usbctlx_submit_async(
                                      hw, ctlx, usercb, usercb_data) == 0 ) {
		result = 0;
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case CTLX_COMPLETE:
		result = hfa384x2host_16(ctlx->inbuf.wridresp.status);
		result &= HFA384x_STATUS_RESULT;

/*
		hw->status = hfa384x2host_16(ctlx->inbuf.wridresp.status);
		hw->resp0 = hfa384x2host_16(ctlx->inbuf.wridresp.resp0);
		hw->resp1 = hfa384x2host_16(ctlx->inbuf.wridresp.resp1);
		hw->resp2 = hfa384x2host_16(ctlx->inbuf.wridresp.resp2);
*/
		break;

	case CTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case CTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case CTLX_REQ_FAILED:
		WLAN_LOG_WARNING("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case CTLX_START:
		result = -EIO;
		break;
	default:
		result = -ERESTARTSYS;
		break;
	} /* switch */

	complete(&ctlx->done);
	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* hfa384x_dormem
*
* Constructs a readmem CTLX and issues it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbrmem() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*	page		MAC address space page (CMD format)
*	offset		MAC address space offset
*	data		Ptr to data buffer to receive read
*	len		Length of the data to read (max == 2048)
*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*
* Returns: 
*	0		success
*	-ETIMEDOUT	timed out waiting for register ready or
*			command completion
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
* Call context:
*	interrupt (wait==0)
*	process (wait==0 || wait==1)
----------------------------------------------------------------*/
int
hfa384x_dormem(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	page,
	UINT16	offset,
	void	*data,
	UINT	len,
	ctlx_usercb_t usercb,
	void	*usercb_data)
{
	int			result;
	hfa384x_usbctlx_t	*ctlx;
	
	DBFENTER;
	ctlx = kmalloc(sizeof(*ctlx), in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	hfa384x_usbctlx_init(ctlx, hw);

	/* Initialize the command */
	ctlx->outbuf.rmemreq.type =    host2hfa384x_16(HFA384x_USB_RMEMREQ);
	ctlx->outbuf.rmemreq.frmlen =  host2hfa384x_16(
					sizeof(ctlx->outbuf.rmemreq.offset) +
					sizeof(ctlx->outbuf.rmemreq.page) +
					len);
	ctlx->outbuf.rmemreq.offset =	host2hfa384x_16(offset);
	ctlx->outbuf.rmemreq.page =	host2hfa384x_16(page);

	WLAN_LOG_DEBUG(4,
		"type=0x%04x frmlen=%d offset=0x%04x page=0x%04x\n",
		ctlx->outbuf.rmemreq.type,
		ctlx->outbuf.rmemreq.frmlen,
		ctlx->outbuf.rmemreq.offset,
		ctlx->outbuf.rmemreq.page);

	WLAN_LOG_DEBUG(4,"pktsize=%d\n", 
		ROUNDUP64(sizeof(ctlx->outbuf.rmemreq)));

	/* Fill the out packet */
	usb_fill_bulk_urb( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), ROUNDUP64(sizeof(ctlx->outbuf.rmemreq)),
		hfa384x_ctlxout_callback, ctlx);
	ctlx->outurb.transfer_flags |= USB_QUEUE_BULK;

	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else if ( hfa384x_usbctlx_submit_async(
	                              hw, ctlx, usercb, usercb_data) == 0 ) {
		result = 0;
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case CTLX_COMPLETE:
		WLAN_LOG_DEBUG(4,"rmemresp:len=%d\n",
			ctlx->inbuf.rmemresp.frmlen);
		memcpy(data, ctlx->inbuf.rmemresp.data, len);
		result = 0;
		break;
	case CTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case CTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case CTLX_REQ_FAILED:
		WLAN_LOG_WARNING("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case CTLX_START:
		result = -EIO;
		break;
	default:
		result = -ERESTARTSYS;
		break;
	} /* switch */

	complete(&ctlx->done);
	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}


	
/*----------------------------------------------------------------
* hfa384x_dowmem
*
* Constructs a writemem CTLX and issues it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbwmem() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*	page		MAC address space page (CMD format)
*	offset		MAC address space offset
*	data		Ptr to data buffer containing write data
*	len		Length of the data to read (max == 2048)
*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*
* Returns: 
*	0		success
*	-ETIMEDOUT	timed out waiting for register ready or
*			command completion
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
* Call context:
*	interrupt (wait==0)
*	process (wait==0 || wait==1)
----------------------------------------------------------------*/
int
hfa384x_dowmem(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	page,
	UINT16	offset,
	void	*data,
	UINT	len,
	ctlx_usercb_t usercb,
	void	*usercb_data)
{
	int			result;
	hfa384x_usbctlx_t	*ctlx;
	
	DBFENTER;
	WLAN_LOG_DEBUG(5, "page=0x%04x offset=0x%04x len=%d\n",
		page,offset,len);

	ctlx = kmalloc(sizeof(*ctlx), in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	hfa384x_usbctlx_init(ctlx, hw);

	/* Initialize the command */
	ctlx->outbuf.wmemreq.type =   host2hfa384x_16(HFA384x_USB_WMEMREQ);
	ctlx->outbuf.wmemreq.frmlen = host2hfa384x_16(
					sizeof(ctlx->outbuf.wmemreq.offset) +
					sizeof(ctlx->outbuf.wmemreq.page) +
					len);
	ctlx->outbuf.wmemreq.offset = host2hfa384x_16(offset);
	ctlx->outbuf.wmemreq.page =   host2hfa384x_16(page);
	memcpy(ctlx->outbuf.wmemreq.data, data, len);

	/* Fill the out packet */
	usb_fill_bulk_urb( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), 
		ROUNDUP64( sizeof(ctlx->outbuf.wmemreq.type) +
			sizeof(ctlx->outbuf.wmemreq.frmlen) +
			sizeof(ctlx->outbuf.wmemreq.offset) +
			sizeof(ctlx->outbuf.wmemreq.page) +
			len),
		hfa384x_ctlxout_callback, 
		ctlx);
	ctlx->outurb.transfer_flags |= USB_QUEUE_BULK;

	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else if ( hfa384x_usbctlx_submit_async(
	                              hw, ctlx, usercb, usercb_data) == 0 ) {
		result = 0;
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case CTLX_COMPLETE:
		result = hfa384x2host_16(ctlx->inbuf.wmemresp.status);
/*
		hw->status = hfa384x2host_16(ctlx->inbuf.wmemresp.status);
		hw->resp0 = hfa384x2host_16(ctlx->inbuf.wmemresp.resp0);
		hw->resp1 = hfa384x2host_16(ctlx->inbuf.wmemresp.resp1);
		hw->resp2 = hfa384x2host_16(ctlx->inbuf.wmemresp.resp2);
*/
		break;
	case CTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case CTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case CTLX_REQ_FAILED:
		WLAN_LOG_WARNING("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case CTLX_START:
		result = -EIO;
		break;
	default:
		result = -ERESTARTSYS;
		break;
	} /* switch */

	complete(&ctlx->done);
	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}

	
/*----------------------------------------------------------------
* hfa384x_drvr_commtallies
*
* Send a commtallies inquiry to the MAC.  Note that this is an async
* call that will result in an info frame arriving sometime later.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	zero		success.
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
int hfa384x_drvr_commtallies( hfa384x_t *hw )
{
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMDCODE_INQ;
	cmd.parm0 = HFA384x_IT_COMMTALLIES;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	hfa384x_docmd(hw, DOASYNC, &cmd, NULL, NULL);
	
	DBFEXIT;
	return 0;
}


/*----------------------------------------------------------------
* hfa384x_drvr_disable
*
* Issues the disable command to stop communications on one of 
* the MACs 'ports'.  Only macport 0 is valid  for stations.
* APs may also disable macports 1-6.  Only ports that have been
* previously enabled may be disabled.
*
* Arguments:
*	hw		device structure
*	macport		MAC port number (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_disable(hfa384x_t *hw, UINT16 macport)
{
	int	result = 0;

	DBFENTER;
	if ((!hw->isap && macport != 0) || 
	    (hw->isap && !(macport <= HFA384x_PORTID_MAX)) ||
	    !(hw->port_enabled[macport]) ){
		result = -EINVAL;
	} else {
		result = hfa384x_cmd_disable(hw, macport);
		if ( result == 0 ) {
			hw->port_enabled[macport] = 0;
		}
	}
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_enable
*
* Issues the enable command to enable communications on one of 
* the MACs 'ports'.  Only macport 0 is valid  for stations.
* APs may also enable macports 1-6.  Only ports that are currently
* disabled may be enabled.
*
* Arguments:
*	hw		device structure
*	macport		MAC port number
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_enable(hfa384x_t *hw, UINT16 macport)
{
	int	result = 0;

	DBFENTER;
	if ((!hw->isap && macport != 0) || 
	    (hw->isap && !(macport <= HFA384x_PORTID_MAX)) ||
	    (hw->port_enabled[macport]) ){
		result = -EINVAL;
	} else {
		result = hfa384x_cmd_enable(hw, macport);
		if ( result == 0 ) {
			hw->port_enabled[macport] = 1;
		}
	}
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_flashdl_enable
*
* Begins the flash download state.  Checks to see that we're not
* already in a download state and that a port isn't enabled.
* Sets the download state and retrieves the flash download
* buffer location, buffer size, and timeout length.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_flashdl_enable(hfa384x_t *hw)
{
	int		result = 0;
	int		i;

	DBFENTER;
	/* Check that a port isn't active */
	for ( i = 0; i < HFA384x_PORTID_MAX; i++) {
		if ( hw->port_enabled[i] ) {
			WLAN_LOG_DEBUG(1,"called when port enabled.\n");
			return -EINVAL; 
		}
	}

	/* Check that we're not already in a download state */
	if ( hw->dlstate != HFA384x_DLSTATE_DISABLED ) {
		return -EINVAL;
	}

	/* Retrieve the buffer loc&size and timeout */
	if ( (result = hfa384x_drvr_getconfig(hw, HFA384x_RID_DOWNLOADBUFFER, 
				&(hw->bufinfo), sizeof(hw->bufinfo))) ) {
		return result;
	}
	hw->bufinfo.page = hfa384x2host_16(hw->bufinfo.page);
	hw->bufinfo.offset = hfa384x2host_16(hw->bufinfo.offset);
	hw->bufinfo.len = hfa384x2host_16(hw->bufinfo.len);
	if ( (result = hfa384x_drvr_getconfig16(hw, HFA384x_RID_MAXLOADTIME, 
				&(hw->dltimeout))) ) {
		return result;
	}
	hw->dltimeout = hfa384x2host_16(hw->dltimeout);

	WLAN_LOG_DEBUG(1,"flashdl_enable\n");

	hw->dlstate = HFA384x_DLSTATE_FLASHENABLED;
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_flashdl_disable
*
* Ends the flash download state.  Note that this will cause the MAC
* firmware to restart.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_flashdl_disable(hfa384x_t *hw)
{
	DBFENTER;
	/* Check that we're already in the download state */
	if ( hw->dlstate != HFA384x_DLSTATE_FLASHENABLED ) {
		return -EINVAL;
	}

	WLAN_LOG_DEBUG(1,"flashdl_enable\n");

	/* There isn't much we can do at this point, so I don't */
	/*  bother  w/ the return value */
	hfa384x_cmd_download(hw, HFA384x_PROGMODE_DISABLE, 0, 0 , 0);
	hw->dlstate = HFA384x_DLSTATE_DISABLED;

	DBFEXIT;
	return 0;
}


/*----------------------------------------------------------------
* hfa384x_drvr_flashdl_write
*
* Performs a FLASH download of a chunk of data. First checks to see
* that we're in the FLASH download state, then sets the download
* mode, uses the aux functions to 1) copy the data to the flash
* buffer, 2) sets the download 'write flash' mode, 3) readback and 
* compare.  Lather rinse, repeat as many times an necessary to get
* all the given data into flash.  
* When all data has been written using this function (possibly 
* repeatedly), call drvr_flashdl_disable() to end the download state
* and restart the MAC.
*
* Arguments:
*	hw		device structure
*	daddr		Card address to write to. (host order)
*	buf		Ptr to data to write.
*	len		Length of data (host order).
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_flashdl_write(
	hfa384x_t	*hw, 
	UINT32		daddr, 
	void		*buf, 
	UINT32		len)
{
	int		result = 0;
	UINT8		*verbuf;
	UINT32		dlbufaddr;
	int		nburns;
	UINT32		burnlen;
	UINT32		burndaddr;
	UINT16		burnlo;
	UINT16		burnhi;
	int		nwrites;
	UINT8		*writebuf;
	UINT16		writepage;
	UINT16		writeoffset;
	UINT32		writelen;
	int		i;
	int		j;

	DBFENTER;
	WLAN_LOG_DEBUG(5,"daddr=0x%08lx len=%ld\n", daddr, len);

	/* Check that we're in the flash download state */
	if ( hw->dlstate != HFA384x_DLSTATE_FLASHENABLED ) {
		return -EINVAL;
	}

	WLAN_LOG_INFO("Download %ld bytes to flash @0x%06lx\n", len, daddr);

	/* Convert to flat address for arithmetic */
	/* NOTE: dlbuffer RID stores the address in AUX format */
	dlbufaddr = HFA384x_ADDR_AUX_MKFLAT(
			hw->bufinfo.page, hw->bufinfo.offset);
	WLAN_LOG_DEBUG(5,
		"dlbuf.page=0x%04x dlbuf.offset=0x%04x dlbufaddr=0x%08lx\n",
		hw->bufinfo.page, hw->bufinfo.offset, dlbufaddr);

	verbuf = kmalloc(hw->bufinfo.len, GFP_ATOMIC);

	if ( verbuf == NULL ) {
		WLAN_LOG_ERROR("Failed to allocate flash verify buffer\n");
		return 1;
	}

#if 0
WLAN_LOG_WARNING("dlbuf@0x%06lx len=%d to=%d\n", dlbufaddr, hw->bufinfo.len, hw->dltimeout);
#endif
	/* Calculations to determine how many fills of the dlbuffer to do
	 * and how many USB wmemreq's to do for each fill.  At this point
	 * in time, the dlbuffer size and the wmemreq size are the same.
	 * Therefore, nwrites should always be 1.  The extra complexity
	 * here is a hedge against future changes.
	 */

	/* Figure out how many times to do the flash programming */
	nburns = len / hw->bufinfo.len;
	nburns += (len % hw->bufinfo.len) ? 1 : 0;

	/* For each flash program cycle, how many USB wmemreq's are needed? */
	nwrites = hw->bufinfo.len / HFA384x_USB_RWMEM_MAXLEN;
	nwrites += (hw->bufinfo.len % HFA384x_USB_RWMEM_MAXLEN) ? 1 : 0;

	/* For each burn */
	for ( i = 0; i < nburns; i++) {
		/* Get the dest address and len */
		burnlen = (len - (hw->bufinfo.len * i)) > hw->bufinfo.len ?
				hw->bufinfo.len : 
				(len - (hw->bufinfo.len * i));
		burndaddr = daddr + (hw->bufinfo.len * i);
		burnlo = HFA384x_ADDR_CMD_MKOFF(burndaddr);
		burnhi = HFA384x_ADDR_CMD_MKPAGE(burndaddr);

		WLAN_LOG_INFO("Writing %ld bytes to flash @0x%06lx\n", 
			burnlen, burndaddr);

		/* Set the download mode */
		result = hfa384x_cmd_download(hw, HFA384x_PROGMODE_NV, 
				burnlo, burnhi, burnlen);
		if ( result ) {
			WLAN_LOG_ERROR("download(NV,lo=%x,hi=%x,len=%lx) "
				"cmd failed, result=%d. Aborting d/l\n",
				burnlo, burnhi, burnlen, result);
			goto exit_proc;
		}

		/* copy the data to the flash download buffer */
		for ( j=0; j < nwrites; j++) {
			writebuf = buf + 
				(i*hw->bufinfo.len) + 
				(j*HFA384x_USB_RWMEM_MAXLEN);
			
			writepage = HFA384x_ADDR_CMD_MKPAGE(
					dlbufaddr + 
					(j*HFA384x_USB_RWMEM_MAXLEN));
			writeoffset = HFA384x_ADDR_CMD_MKOFF(
					dlbufaddr + 
					(j*HFA384x_USB_RWMEM_MAXLEN));

			writelen = burnlen-(j*HFA384x_USB_RWMEM_MAXLEN);
			writelen = writelen  > HFA384x_USB_RWMEM_MAXLEN ?
					HFA384x_USB_RWMEM_MAXLEN :
					writelen;

			result = hfa384x_dowmem( hw, DOWAIT,
					writepage, 
					writeoffset, 
					writebuf, 
					writelen, 
					NULL, NULL);
#if 0

Comment out for debugging, assume the write was successful.
			if (result) {
				WLAN_LOG_ERROR(
					"Write to dl buffer failed, "
					"result=0x%04x. Aborting.\n", 
					result);
				goto exit_proc;
			}
#endif

		}

		/* set the download 'write flash' mode */
		result = hfa384x_cmd_download(hw, 
				HFA384x_PROGMODE_NVWRITE, 
				0,0,0);
		if ( result ) {
			WLAN_LOG_ERROR(
				"download(NVWRITE,lo=%x,hi=%x,len=%lx) "
				"cmd failed, result=%d. Aborting d/l\n",
				burnlo, burnhi, burnlen, result);
			goto exit_proc;
		}

		/* TODO: We really should do a readback and compare. */
	}

exit_proc:

	/* Leave the firmware in the 'post-prog' mode.  flashdl_disable will */
	/*  actually disable programming mode.  Remember, that will cause the */
	/*  the firmware to effectively reset itself. */
	
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_getconfig
*
* Performs the sequence necessary to read a config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (host order)
*	buf		host side record buffer.  Upon return it will
*			contain the body portion of the record (minus the 
*			RID and len).
*	len		buffer length (in bytes, should match record length)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*	-ENODATA 	length mismatch between argument and retrieved
*			record.
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_getconfig(hfa384x_t *hw, UINT16 rid, void *buf, UINT16 len)
{
	int 			result;
	DBFENTER;

	result = hfa384x_dorrid(hw, DOWAIT, rid, buf, len, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_getconfig16
*
* Performs the sequence necessary to read a 16 bit config/info item
* and convert it to host order.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	val		ptr to 16 bit buffer to receive value (in host order)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_getconfig16(hfa384x_t *hw, UINT16 rid, void *val)
{
	int		result;
	DBFENTER;
	result = hfa384x_drvr_getconfig(hw, rid, val, sizeof(UINT16));
	if ( result == 0 ) {
		*((UINT16*)val) = hfa384x2host_16(*((UINT16*)val));
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_getconfig32
*
* Performs the sequence necessary to read a 32 bit config/info item
* and convert it to host order.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	val		ptr to 32 bit buffer to receive value (in host order)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_getconfig32(hfa384x_t *hw, UINT16 rid, void *val)
{
	int		result;
	DBFENTER;
	result = hfa384x_drvr_getconfig(hw, rid, val, sizeof(UINT32));
	if ( result == 0 ) {
		*((UINT32*)val) = hfa384x2host_32(*((UINT32*)val));
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_getconfig_async
*
* Performs the sequence necessary to perform an async read of
* of a config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (host order)
*	buf		host side record buffer.  Upon return it will
*			contain the body portion of the record (minus the 
*			RID and len).
*	len		buffer length (in bytes, should match record length)
*	cbfn		caller supplied callback, called when the command 
*			is done (successful or not).
*	cbfndata	pointer to some caller supplied data that will be
*			passed in as an argument to the cbfn.
*
* Returns: 
*	nothing		the cbfn gets a status argument identifying if
*			any errors occur.
* Side effects:
*	Queues an hfa384x_usbcmd_t for subsequent execution.
*
* Call context:
*	Any
----------------------------------------------------------------*/
int
hfa384x_drvr_getconfig_async(
	hfa384x_t		*hw, 
	UINT16			rid, 
	ctlx_usercb_t		usercb, 
	void			*usercb_data)
{
	return hfa384x_dorrid(hw, DOASYNC, rid, NULL, 0, usercb, usercb_data);
}


/*----------------------------------------------------------------
* hfa384x_drvr_handover
*
* Sends a handover notification to the MAC.
*
* Arguments:
*	hw		device structure
*	addr		address of station that's left
*
* Returns: 
*	zero		success.
*	-ERESTARTSYS	received signal while waiting for semaphore.
*	-EIO		failed to write to bap, or failed in cmd.
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
int hfa384x_drvr_handover( hfa384x_t *hw, UINT8 *addr)
{
        DBFENTER;
	WLAN_LOG_ERROR("Not currently supported in USB!\n");
	DBFEXIT;
	return -EIO;
}

/*----------------------------------------------------------------
* hfa384x_drvr_low_level
*
* Write test commands to the card.  Some test commands don't make
* sense without prior set-up.  For example, continous TX isn't very
* useful until you set the channel.  That functionality should be
*
* Side effects:
*
* Call context:
*      process thread 
* -----------------------------------------------------------------*/
int hfa384x_drvr_low_level(hfa384x_t *hw, hfa384x_metacmd_t *cmd)
{
	int             result;
	DBFENTER;
	
	/* Do i need a host2hfa... conversion ? */

	result = hfa384x_docmd(hw, DOWAIT, cmd, NULL, NULL);

	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* hfa384x_drvr_mmi_read
*
* Read mmi registers.  mmi is intersil-speak for the baseband
* processor registers.
*
* Arguments:
*       hw              device structure
*       register        The test register to be accessed (must be even #).
*
* Returns:
*       0               success
*       >0              f/w reported error - f/w status code
*       <0              driver reported error
*
* Side effects:
*
* Call context:
*       process
----------------------------------------------------------------*/
int hfa384x_drvr_mmi_read(hfa384x_t *hw, UINT32 addr, UINT32 *resp)
{
#if 0
        int             result = 0;
        UINT16  cmd_code = (UINT16) 0x30;
        UINT16 param = (UINT16) addr;
        DBFENTER;

        /* Do i need a host2hfa... conversion ? */
        result = hfa384x_docmd_wait(hw, cmd_code, param, 0, 0);

        DBFEXIT;
        return result;
#endif
return 0;
}

/*----------------------------------------------------------------
* hfa384x_drvr_mmi_write
*
* Read mmi registers.  mmi is intersil-speak for the baseband
* processor registers.
*
* Arguments:
*       hw              device structure
*       addr            The test register to be accessed (must be even #).
*       data            The data value to write to the register.
*
* Returns:
*       0               success
*       >0              f/w reported error - f/w status code
*       <0              driver reported error
*
* Side effects:
*
* Call context:
*       process
----------------------------------------------------------------*/

int
hfa384x_drvr_mmi_write(hfa384x_t *hw, UINT32 addr, UINT32 data)
{
#if 0
        int             result = 0;
        UINT16  cmd_code = (UINT16) 0x31;
        UINT16 param0 = (UINT16) addr;
        UINT16 param1 = (UINT16) data;
        DBFENTER;

        WLAN_LOG_DEBUG(1,"mmi write : addr = 0x%08lx\n", addr);
        WLAN_LOG_DEBUG(1,"mmi write : data = 0x%08lx\n", data);

        /* Do i need a host2hfa... conversion ? */
        result = hfa384x_docmd_wait(hw, cmd_code, param0, param1, 0);

        DBFEXIT;
        return result;
#endif
return 0;
}


/*----------------------------------------------------------------
* hfa384x_drvr_ramdl_disable
*
* Ends the ram download state.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int 
hfa384x_drvr_ramdl_disable(hfa384x_t *hw)
{
	DBFENTER;
	/* Check that we're already in the download state */
	if ( hw->dlstate != HFA384x_DLSTATE_RAMENABLED ) {
		return -EINVAL;
	}

	WLAN_LOG_DEBUG(3,"ramdl_disable()\n");

	/* There isn't much we can do at this point, so I don't */
	/*  bother  w/ the return value */
	hfa384x_cmd_download(hw, HFA384x_PROGMODE_DISABLE, 0, 0 , 0);
	hw->dlstate = HFA384x_DLSTATE_DISABLED;

	DBFEXIT;
	return 0;
}


/*----------------------------------------------------------------
* hfa384x_drvr_ramdl_enable
*
* Begins the ram download state.  Checks to see that we're not
* already in a download state and that a port isn't enabled.
* Sets the download state and calls cmd_download with the 
* ENABLE_VOLATILE subcommand and the exeaddr argument.
*
* Arguments:
*	hw		device structure
*	exeaddr		the card execution address that will be 
*                       jumped to when ramdl_disable() is called
*			(host order).
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_ramdl_enable(hfa384x_t *hw, UINT32 exeaddr)
{
	int		result = 0;
	UINT16		lowaddr;
	UINT16		hiaddr;
	int		i;
	DBFENTER;
	/* Check that a port isn't active */
	for ( i = 0; i < HFA384x_PORTID_MAX; i++) {
		if ( hw->port_enabled[i] ) {
			WLAN_LOG_ERROR(
				"Can't download with a macport enabled.\n");
			return -EINVAL; 
		}
	}

	/* Check that we're not already in a download state */
	if ( hw->dlstate != HFA384x_DLSTATE_DISABLED ) {
		WLAN_LOG_ERROR(
			"Download state not disabled.\n");
		return -EINVAL;
	}

	WLAN_LOG_DEBUG(3,"ramdl_enable, exeaddr=0x%08lx\n", exeaddr);

	/* Call the download(1,addr) function */
	lowaddr = HFA384x_ADDR_CMD_MKOFF(exeaddr);
	hiaddr =  HFA384x_ADDR_CMD_MKPAGE(exeaddr);

	result = hfa384x_cmd_download(hw, HFA384x_PROGMODE_RAM, 
			lowaddr, hiaddr, 0);

	if ( result == 0) {
		/* Set the download state */
		hw->dlstate = HFA384x_DLSTATE_RAMENABLED;
	} else {
		WLAN_LOG_DEBUG(1,
			"cmd_download(0x%04x, 0x%04x) failed, result=%d.\n",
			lowaddr,
			hiaddr, 
			result);
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_ramdl_write
*
* Performs a RAM download of a chunk of data. First checks to see
* that we're in the RAM download state, then uses the [read|write]mem USB
* commands to 1) copy the data, 2) readback and compare.  The download
* state is unaffected.  When all data has been written using
* this function, call drvr_ramdl_disable() to end the download state
* and restart the MAC.
*
* Arguments:
*	hw		device structure
*	daddr		Card address to write to. (host order)
*	buf		Ptr to data to write.
*	len		Length of data (host order).
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_ramdl_write(hfa384x_t *hw, UINT32 daddr, void* buf, UINT32 len)
{
	int		result = 0;
	int		nwrites;
	UINT8		*data = buf;
	int		i;
	UINT32		curraddr;
	UINT16		currpage;
	UINT16		curroffset;
	UINT16		currlen;
	DBFENTER;
	/* Check that we're in the ram download state */
	if ( hw->dlstate != HFA384x_DLSTATE_RAMENABLED ) {
		return -EINVAL;
	}

	WLAN_LOG_INFO("Writing %ld bytes to ram @0x%06lx\n", len, daddr);

	/* How many dowmem calls?  */
	nwrites = len / HFA384x_USB_RWMEM_MAXLEN;
	nwrites += len % HFA384x_USB_RWMEM_MAXLEN ? 1 : 0;

	/* Do blocking wmem's */
	for(i=0; i < nwrites; i++) {
		/* make address args */
		curraddr = daddr + (i * HFA384x_USB_RWMEM_MAXLEN);
		currpage = HFA384x_ADDR_CMD_MKPAGE(curraddr);
		curroffset = HFA384x_ADDR_CMD_MKOFF(curraddr);
		currlen = len - (i * HFA384x_USB_RWMEM_MAXLEN);
		if ( currlen > HFA384x_USB_RWMEM_MAXLEN) {
			currlen = HFA384x_USB_RWMEM_MAXLEN;
		}

	 	/* Do blocking ctlx */
		result = hfa384x_dowmem( hw, DOWAIT,
				currpage, 
				curroffset, 
				data + (i*HFA384x_USB_RWMEM_MAXLEN), 
				currlen, 
				NULL, NULL);

		if (result) break;

		/* TODO: We really should have a readback. */
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_readpda
*
* Performs the sequence to read the PDA space.  Note there is no
* drvr_writepda() function.  Writing a PDA is
* generally implemented by a calling component via calls to 
* cmd_download and writing to the flash download buffer via the 
* aux regs.
*
* Arguments:
*	hw		device structure
*	buf		buffer to store PDA in
*	len		buffer length
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*	-ETIMEOUT	timout waiting for the cmd regs to become
*			available, or waiting for the control reg
*			to indicate the Aux port is enabled.
*	-ENODATA	the buffer does NOT contain a valid PDA.
*			Either the card PDA is bad, or the auxdata
*			reads are giving us garbage.

*
* Side effects:
*
* Call context:
*	process or non-card interrupt.
----------------------------------------------------------------*/
int hfa384x_drvr_readpda(hfa384x_t *hw, void *buf, UINT len)
{
	int		result = 0;
	UINT16		*pda = buf;
	int		pdaok = 0;
	int		morepdrs = 1;
	int		currpdr = 0;	/* word offset of the current pdr */
	int		i;
	UINT16		pdrlen;		/* pdr length in bytes, host order */
	UINT16		pdrcode;	/* pdr code, host order */
	UINT16		currpage;
	UINT16		curroffset;
	struct pdaloc {
		UINT32	cardaddr;
		UINT16	auxctl;
	} pdaloc[] =
	{
		{ HFA3842_PDA_BASE,		0},
		{ HFA3841_PDA_BASE,		0}, 
		{ HFA3841_PDA_BOGUS_BASE,	0}
	};

	DBFENTER;

	/* Read the pda from each known address.  */
	for ( i = 0; i < (sizeof(pdaloc)/sizeof(pdaloc[0])); i++) {
		/* Make address */
		currpage = HFA384x_ADDR_CMD_MKPAGE(pdaloc[i].cardaddr);
		curroffset = HFA384x_ADDR_CMD_MKOFF(pdaloc[i].cardaddr);
	
		result = hfa384x_dormem(hw, DOWAIT,
			currpage,
			curroffset,
			buf,
			len,		/* units of bytes */
			NULL, NULL);

		if (result) {
			WLAN_LOG_WARNING(
					  "Read from index %d failed, continuing\n",
				i );
			if ( i >= (sizeof(pdaloc)/sizeof(pdaloc[0])) ){
				break;
			} else {
				continue;
			}
		}

		/* Test for garbage */
		pdaok = 1;	/* intially assume good */
		morepdrs = 1;
		while ( pdaok && morepdrs ) {
			pdrlen = hfa384x2host_16(pda[currpdr]) * 2;
			pdrcode = hfa384x2host_16(pda[currpdr+1]);
			/* Test the record length */
			if ( pdrlen > HFA384x_PDR_LEN_MAX || pdrlen == 0) {
				WLAN_LOG_ERROR("pdrlen invalid=%d\n", 
					pdrlen);
				pdaok = 0;
				break;
			}
			/* Test the code */
			if ( !hfa384x_isgood_pdrcode(pdrcode) ) {
				WLAN_LOG_ERROR("pdrcode invalid=%d\n", 
					pdrcode);
				pdaok = 0;
				break;
			}
			/* Test for completion */
			if ( pdrcode == HFA384x_PDR_END_OF_PDA) {
				morepdrs = 0;
			}
	
			/* Move to the next pdr (if necessary) */
			if ( morepdrs ) {
				/* note the access to pda[], need words here */
				currpdr += hfa384x2host_16(pda[currpdr]) + 1;
			}
		}	
		if ( pdaok ) {
			WLAN_LOG_DEBUG(2,
				"PDA Read from 0x%08lx in %s space.\n",
				pdaloc[i].cardaddr, 
				pdaloc[i].auxctl == 0 ? "EXTDS" :
				pdaloc[i].auxctl == 1 ? "NV" :
				pdaloc[i].auxctl == 2 ? "PHY" :
				pdaloc[i].auxctl == 3 ? "ICSRAM" : 
				"<bogus auxctl>");
			break;
		} 
	}
	result = pdaok ? 0 : -ENODATA;

	if ( result ) {
		WLAN_LOG_DEBUG(3,"Failure: pda is not okay\n");
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_setconfig
*
* Performs the sequence necessary to write a config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	buf		host side record buffer
*	len		buffer length (in bytes)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_setconfig(hfa384x_t *hw, UINT16 rid, void *buf, UINT16 len)
{
	return hfa384x_dowrid(hw, DOWAIT, rid, buf, len, NULL, NULL);
}


/*----------------------------------------------------------------
* hfa384x_drvr_setconfig_async
*
* Performs the sequence necessary to write a config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	buf		host side record buffer
*	len		buffer length (in bytes)
*	usercb		completion callback
*	usercb_data	completion callback argument
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_setconfig_async(
	hfa384x_t	*hw,
	UINT16		rid,
	void		*buf,
	UINT16		len,
	ctlx_usercb_t	usercb,
	void		*usercb_data)
{
	return hfa384x_dowrid(hw, DOASYNC, rid, buf, len, usercb, usercb_data);
}


/*----------------------------------------------------------------
* hfa384x_drvr_start
*
* Issues the MAC initialize command, sets up some data structures,
* and enables the interrupts.  After this function completes, the
* low-level stuff should be ready for any/all commands.
*
* Arguments:
*	hw		device structure
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_start(hfa384x_t *hw)
{
	int		result;
	DBFENTER;

	if (usb_clear_halt(hw->usb, usb_rcvbulkpipe(hw->usb, hw->endp_in))) {
		WLAN_LOG_ERROR(
			"Failed to reset bulk in endpoint.\n");
	}

	if (usb_clear_halt(hw->usb, usb_sndbulkpipe(hw->usb, hw->endp_out))) {
		WLAN_LOG_ERROR(
			"Failed to reset bulk out endpoint.\n");
	}

	/* Synchronous unlink, in case we're trying to restart the driver */
	usb_unlink_urb(&hw->rx_urb);

	/* Post the IN urb */
	result = submit_rx_urb(hw, GFP_KERNEL);
	if (result != 0) {
		WLAN_LOG_ERROR(
			"Fatal, failed to submit RX URB, result=%d\n",
			result);
		goto done;
	}

	/* call initialize */
	result = hfa384x_cmd_initialize(hw);
	if (result != 0) {
		usb_unlink_urb(&hw->rx_urb);
		WLAN_LOG_ERROR(
			"cmd_initialize() failed, result=%d\n",
			result);
		goto done;
	}

	hw->state = HFA384x_STATE_RUNNING;
	
done:
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_stop
*
* Shuts down the MAC to the point where it is safe to unload the
* driver.  Any subsystem that may be holding a data or function
* ptr into the driver must be cleared/deinitialized.
*
* Arguments:
*	hw		device structure
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_stop(hfa384x_t *hw)
{
	int	result = 0;
	int	i;
	DBFENTER;

	flush_scheduled_work();

	/* There's no need for spinlocks here. The USB "disconnect"
	 * function sets this "removed" flag and then calls us.
	 */
	if ( !hw->usb_removed ) {
		/* Call initialize to leave the MAC in its 'reset' state */
		hfa384x_cmd_initialize(hw);

		/* Cancel the rxurb */
		usb_unlink_urb(&hw->rx_urb);
	}

	hw->link_status = HFA384x_LINK_NOTCONNECTED;
	hw->state = HFA384x_STATE_INIT;

	/* Clear all the port status */
	for ( i = 0; i < HFA384x_NUMPORTS_MAX; i++) {
		hw->port_enabled[i] = 0;
	}

	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* hfa384x_drvr_txframe
*
* Takes a frame from prism2sta and queues it for transmission.
*
* Arguments:
*	hw		device structure
*	skb		packet buffer struct.  Contains an 802.11
*			data frame.
*       p80211_hdr      points to the 802.11 header for the packet.
* Returns: 
*	0		Success and more buffs available
*	1		Success but no more buffs
*	2		Allocation failure
*	4		Buffer full or queue busy
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
int hfa384x_drvr_txframe(hfa384x_t *hw, struct sk_buff *skb, p80211_hdr_t *p80211_hdr, p80211_metawep_t *p80211_wep)

{
	int		usbpktlen = sizeof(hfa384x_tx_frame_t);
	int		result;
	int		ret;
	char		*ptr;

	DBFENTER;

	if (hw->tx_urb.status == -EINPROGRESS) {
		WLAN_LOG_WARNING("TX URB already in use\n");
		result = 3; 
		goto exit;
	}

	/* Build Tx frame structure */
	/* Set up the control field */
	memset(&hw->txbuff.txfrm.desc, 0, sizeof(hw->txbuff.txfrm.desc));

	/* Setup the usb type field */
	hw->txbuff.type = host2hfa384x_16(HFA384x_USB_TXFRM);

	/* Set up the sw_support field to identify this frame */
	hw->txbuff.txfrm.desc.sw_support = 0x0123;

/* Tx complete and Tx exception disable per dleach.  Might be causing 
 * buf depletion 
 */
//#define DOEXC  SLP -- doboth breaks horribly under load, doexc less so.
#if defined(DOBOTH)
	hw->txbuff.txfrm.desc.tx_control = 
		HFA384x_TX_MACPORT_SET(0) | HFA384x_TX_STRUCTYPE_SET(1) | 
		HFA384x_TX_TXEX_SET(1) | HFA384x_TX_TXOK_SET(1);	
#elif defined(DOEXC)
	hw->txbuff.txfrm.desc.tx_control = 
		HFA384x_TX_MACPORT_SET(0) | HFA384x_TX_STRUCTYPE_SET(1) |
		HFA384x_TX_TXEX_SET(1) | HFA384x_TX_TXOK_SET(0);	
#else
	hw->txbuff.txfrm.desc.tx_control = 
		HFA384x_TX_MACPORT_SET(0) | HFA384x_TX_STRUCTYPE_SET(1) |
		HFA384x_TX_TXEX_SET(0) | HFA384x_TX_TXOK_SET(0);	
#endif
	hw->txbuff.txfrm.desc.tx_control = 
		host2hfa384x_16(hw->txbuff.txfrm.desc.tx_control);

	/* copy the header over to the txdesc */
	memcpy(&(hw->txbuff.txfrm.desc.frame_control), p80211_hdr, sizeof(p80211_hdr_t));

	/* if we're using host WEP, increase size by IV+ICV */
	if (p80211_wep->data) {
		hw->txbuff.txfrm.desc.data_len = host2hfa384x_16(skb->len+8);
		// hw->txbuff.txfrm.desc.tx_control |= HFA384x_TX_NOENCRYPT_SET(1);
		usbpktlen+=8;
	} else {
		hw->txbuff.txfrm.desc.data_len = host2hfa384x_16(skb->len);
	}

	usbpktlen += skb->len;

	/* copy over the WEP IV if we are using host WEP */
	ptr = hw->txbuff.txfrm.data;
	if (p80211_wep->data) {
		memcpy(ptr, p80211_wep->iv, sizeof(p80211_wep->iv));
		ptr+= sizeof(p80211_wep->iv);
		memcpy(ptr, p80211_wep->data, skb->len);
	} else {
		memcpy(ptr, skb->data, skb->len);
	}
	/* copy over the packet data */
	ptr+= skb->len;

	/* copy over the WEP ICV if we are using host WEP */
	if (p80211_wep->data) {
		memcpy(ptr, p80211_wep->icv, sizeof(p80211_wep->icv));
	}

	/* Send the USB packet */	
	usb_fill_bulk_urb( &(hw->tx_urb), hw->usb,
	               usb_sndbulkpipe(hw->usb, hw->endp_out),
	               &(hw->txbuff), ROUNDUP64(usbpktlen),
	               hfa384x_usbout_callback, hw->wlandev );
	hw->tx_urb.transfer_flags = USB_QUEUE_BULK;

	result = 1;
	ret = submit_tx_urb(hw, &hw->tx_urb, GFP_ATOMIC);
	if ( ret != 0 ) {
		WLAN_LOG_ERROR(
			"submit_tx_urb() failed, error=%d\n", ret);
		result = 3;
	}

 exit:
	DBFEXIT;
	return result;
}

void hfa384x_tx_timeout(wlandevice_t *wlandev)
{
	hfa384x_t	*hw = wlandev->priv;
	
	DBFENTER;
    /* Note the bitwise OR, not the logical OR. */
	if ( !test_and_set_bit(WORK_TX_HALT, &hw->work_flags) |
	     !test_and_set_bit(WORK_RX_HALT, &hw->work_flags) )
		schedule_work(&hw->usb_work);
	DBFEXIT;
}

/*----------------------------------------------------------------
* hfa384x_usbctlx_cancel
*
* This CTLX must be marked as "dead".
*
* Arguments:
*	ctlx	ptr to a ctlx structure
*
* Returns:
*	Error code from the URB unlink, or -ENODEV
*
* Side effects:
*
* Call context:
*	Either process or interrupt
----------------------------------------------------------------*/
int hfa384x_usbctlx_cancel(hfa384x_usbctlx_t *ctlx)
{
	hfa384x_t	*hw = ctlx->hw;
	unsigned long	flags;

	spin_lock_irqsave(&hw->ctlxq.lock, flags);

	if ( hw->usb_removed ) {
		/* We have been unplugged, and other
		 * clean-up is currently in progress.
		 */
		spin_unlock_irqrestore(&hw->ctlxq.lock, flags);
		return -EINPROGRESS;
	}

	list_move_tail(&ctlx->list, &hw->ctlxq.finished);
	ctlx->state = CTLX_REQ_FAILED;

	del_timer(&ctlx->reqtimer);
	del_timer(&ctlx->resptimer);

	spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

	return usb_unlink_urb(&ctlx->outurb);
}

/*----------------------------------------------------------------
* hfa384x_usbctlx_cancel_async
*
* Mark the CTLX dead asynchronously, and ensure that the
* next command on the queue is run afterwards.
*
* Arguments:
*	ctlx	ptr to a CTLX structure
*
* Returns:
*	Error code from hfa384x_usbctlx_cancel
*
* Call context:
*	Either process or interrupt, but presumably interrupt
----------------------------------------------------------------*/
int hfa384x_usbctlx_cancel_async(hfa384x_usbctlx_t *ctlx)
{
	int ret;

	ctlx->outurb.transfer_flags |= URB_ASYNC_UNLINK;
	ret = hfa384x_usbctlx_cancel(ctlx);

	if (ret != -EINPROGRESS) {
		hfa384x_t	*hw = ctlx->hw;

		/* The OUT URB had either already completed
		 * or was still in the pending queue, so the
		 * URB's completion function will not be called.
		 * We will have to complete the CTLX ourselves.
		 */
		hfa384x_usbctlx_complete(ctlx);

		/* Now run the next command on the queue. */
		/* DON'T FORGET THAT WE HAVE COMPLETED THE CTLX,
		 * SO DON'T DEREFERENCE ITS POINTER AGAIN! */
		hfa384x_usbctlxq_run(&hw->ctlxq);
	}

	return ret;
}

/*----------------------------------------------------------------
* hfa384x_usbctlx_init
*
* Generic construction for a CTLX object.
*
* Arguments:
* 	ctlx	Pointer to raw CTLX
* 	hw	Pointer to constructed hfa384x_t object
*
* Returns:
*	Nothing.
*
* Side effects:
*
* Call context:
*	Process
----------------------------------------------------------------*/
void hfa384x_usbctlx_init(hfa384x_usbctlx_t *ctlx, hfa384x_t *hw)
{
	memset(ctlx, 0, sizeof(*ctlx));

	ctlx->hw = hw;
	ctlx->state = CTLX_START;

	init_completion(&ctlx->done);
	usb_init_urb(&ctlx->outurb);
	INIT_DEFERRED_TASK(ctlx->async_bh, hfa384x_usbctlx_complete_async, ctlx);

	init_timer(&ctlx->resptimer);
	ctlx->resptimer.function = hfa384x_usbctlx_resptimerfn;
	ctlx->resptimer.data = (unsigned long)ctlx;

	init_timer(&ctlx->reqtimer);
	ctlx->reqtimer.function = hfa384x_usbctlx_reqtimerfn;
	ctlx->reqtimer.data = (unsigned long)ctlx;
}

/*----------------------------------------------------------------
* hfa384x_usbctlx_complete
*
* A CTLX has completed.  It may have been successful, it may not
* have been. At this point, the CTLX should be quiescent.  The URBs
* aren't active and the timers should have been stopped.
*
* Arguments:
*	ctlx		ptr to a ctlx structure
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	Either, assume interrupt
----------------------------------------------------------------*/
void hfa384x_usbctlx_complete(hfa384x_usbctlx_t *ctlx)
{
	hfa384x_t		*hw = ctlx->hw;
	unsigned long		flags;

	DBFENTER;

	/* Timers have been stopped, and ctlx should be in 
	 * a terminal state.
	 */
	spin_lock_irqsave(&hw->ctlxq.lock, flags);

 	/* Handling depends on state */
	switch(ctlx->state) {
	case CTLX_COMPLETE:
	case CTLX_REQSUBMIT_FAIL:
	case CTLX_REQ_FAILED:
	case CTLX_REQ_TIMEOUT:
		if ( !hw->usb_removed ) {
			if ( ctlx->is_async ) {
				/* Retire the CTLX from the active queue */
				list_move_tail(&ctlx->list, &hw->ctlxq.finished);

				/* We are currently in IRQ context, so defer
				 * calling the async completion handler.
				 */
				SCHEDULE_DEFERRED_TASK(ctlx->async_bh);
			}
			else {
				/* Remove CTLX from whichever queue it is on */
				list_del(&ctlx->list);

				ctlx->wanna_wakeup = 1;
				wake_up_interruptible(&hw->cmdq);
			}
		}
		spin_unlock_irqrestore(&hw->ctlxq.lock, flags);
		break;

	default:
		if ( !hw->usb_removed ) {
			list_move_tail(&ctlx->list, &hw->ctlxq.finished);
		}
		spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

		WLAN_LOG_ERROR("Called, CTLX not in terminating state.\n");
		/* Things are really bad if this happens. Just throw
		 * the CTLX onto the garbage pile. At least then it
		 * will still be destroyed when the adapter in unplugged.
		 */
		break;
	} /* switch */

	DBFEXIT;
}

/*----------------------------------------------------------------
* hfa384x_usbctlx_complete_async
*
* A CTLX has completed.  It may have been successful, it may not
* have been. At this point, the CTLX should be quiescent.  The URBs
* aren't active and the timers should have been stopped.
*
* Arguments:
*	ctlx	ptr to a ctlx structure
*
* Returns:
*	nothing
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
static void
hfa384x_usbctlx_complete_async(deferred_data_t data)
{
	hfa384x_usbctlx_t	*ctlx = (hfa384x_usbctlx_t*)data;
	hfa384x_t		*hw = ctlx->hw;
	unsigned long		flags;
	DBFENTER;

	switch(hfa384x2host_16(ctlx->outbuf.type)) {
	case HFA384x_USB_CMDREQ:
		hfa384x_cbcmd(hw, ctlx);
		break;
	case HFA384x_USB_WRIDREQ:
		hfa384x_cbwrid(hw, ctlx);
		break;
	case HFA384x_USB_RRIDREQ:
		hfa384x_cbrrid(hw, ctlx);
		break;
	case HFA384x_USB_WMEMREQ:
		hfa384x_cbwmem(hw, ctlx);
		break;
	case HFA384x_USB_RMEMREQ:
		hfa384x_cbrmem(hw, ctlx);
		break;
	default:
		WLAN_LOG_ERROR( "unknown reqtype=%d, ignored.\n",
		                ctlx->outbuf.type);
		break;
	} /* switch */

	/* If we're shutting down then the disconnect
	 * handler has to do this, not us.
	 */
	spin_lock_irqsave(&hw->ctlxq.lock, flags);
	if ( !hw->usb_removed ) {
		list_del(&ctlx->list);
		complete(&ctlx->done);
		kfree(ctlx);
	}
	spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

	DBFEXIT;
}

/*----------------------------------------------------------------
* hfa384x_usbctlxq_enqueue_run
*
* Adds a new item to the queue and makes sure there's an item 
* running.
*
* Arguments:
*	ctlxq		queue structure.
*	cmd		new command
*
* Returns: 
*	0       - command queued
*	-ENODEV - command not queued
*
* Side effects:
*
* Call context:
*	any
----------------------------------------------------------------*/
int
hfa384x_usbctlxq_enqueue_run(
	hfa384x_usbctlxq_t	*ctlxq, 
	hfa384x_usbctlx_t	*ctlx)
{
	int		result;
	unsigned long	flags;
	DBFENTER;

	/* acquire lock */
	spin_lock_irqsave(&ctlxq->lock, flags);

	if ( ctlx->hw->usb_removed ) {
		spin_unlock_irqrestore(&ctlxq->lock, flags);
		result = -ENODEV;
		goto done;
	}

	/* Add item to the list */
	list_add_tail(&ctlx->list, &ctlxq->pending);

	/* Set state to QUEUED */
	ctlx->state = CTLX_QUEUED;

	/* release lock */
	spin_unlock_irqrestore(&ctlxq->lock, flags);

	hfa384x_usbctlxq_run(ctlxq);
	result = 0;

	done:
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_usbctlxq_run
*
* Checks to see if the head item is running.  If not, starts it.
*
* Arguments:
*	ctlxq		queue structure.
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	any
----------------------------------------------------------------*/
void
hfa384x_usbctlxq_run(
	hfa384x_usbctlxq_t	*ctlxq)
{
	unsigned long		flags;
	DBFENTER;

	/* acquire lock */
	spin_lock_irqsave(&ctlxq->lock, flags);

	/* Only one active CTLX at any one time, because there's no
	 * other (reliable) way to match the response URB to the
	 * correct CTLX.
	 */
	if ( !list_empty(&ctlxq->active) )
		goto unlock;

	while ( !list_empty(&ctlxq->pending) ) {
		hfa384x_usbctlx_t	*head;
		hfa384x_t		*hw;
		int			result;

		/* This is the first pending command */
		head = list_entry(ctlxq->pending.next, hfa384x_usbctlx_t, list);
		hw = head->hw;

		/* Check whether the hardware has been removed. If it has then
		 * everything is about to get cleaned up!
		 */
		if ( hw->usb_removed ||
		     test_bit(WORK_TX_HALT, &hw->work_flags) )
			break;

		/* We need to split this off to avoid a race condition */
		list_move_tail(&head->list, &ctlxq->active);

		/* Run the queue: submit the URB and set its state to
		 * CTLX_REQ_SUBMITTED.
		 */
		if ((result = SUBMIT_URB(&head->outurb, GFP_ATOMIC)) == 0) {
			/* This CTLX is now running on the active queue */
			head->state = CTLX_REQ_SUBMITTED;

			/* Start the IN wait timer */
			head->resptimer.expires = jiffies + 2*HZ;
			add_timer(&head->resptimer);

			/* Start the OUT wait timer */
			head->reqtimer.expires = jiffies + HZ;
			add_timer(&head->reqtimer);

			break;
		}

		if (result == -EPIPE) {
			/* The OUT pipe needs resetting, so put
			 * this CTLX back in the "pending" queue
			 * and schedule a reset ...
			 */
			WLAN_LOG_WARNING("%s tx pipe stalled: requesting reset\n",
			                 hw->wlandev->netdev->name);
			list_move(&head->list, &ctlxq->pending);
			set_bit(WORK_TX_HALT, &hw->work_flags);
			schedule_work(&hw->usb_work);
			break;
		}

		head->state = CTLX_REQSUBMIT_FAIL;

		/* release lock */
		spin_unlock_irqrestore(&ctlxq->lock, flags);

		WLAN_LOG_ERROR(
		        "Fatal, failed to submit command urb. error=%d\n",
		        result);

		hfa384x_usbctlx_complete(head);

		/* Reacquire lock before resuming loop.
		 * This brief window of being unlocked
		 * means that we must retest our "have
		 * we been unplugged?" flag.
		 */
		spin_lock_irqsave(&ctlxq->lock, flags);
	} /* while */

	unlock:
	/* release lock */
	spin_unlock_irqrestore(&ctlxq->lock, flags);

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_usbin_callback
*
* Callback for URBs on the BULKIN endpoint.
*
* Arguments:
*	urb		ptr to the completed urb
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
void hfa384x_usbin_callback(struct urb *urb)
#else
void hfa384x_usbin_callback(struct urb *urb, struct pt_regs *regs)
#endif
{
	wlandevice_t		*wlandev = urb->context;
	hfa384x_t		*hw;
	hfa384x_usbin_t		*usbin = urb->transfer_buffer;
	int			result;
	int                     urb_status;
	UINT16			type;

	enum USBIN_ACTION {
		HANDLE,
		RESUBMIT,
		ABORT
	} action;

	DBFENTER;

	if ( !wlandev ||
	     !wlandev->netdev || 
	     !netif_device_present(wlandev->netdev) )
		goto exit;

	hw = wlandev->priv;
	if (!hw)
		goto exit;

	/* Check for error conditions within the URB */
	switch (urb->status) {
	case 0:
		action = HANDLE;

		/* Check for short packet */
		if ( urb->actual_length == 0 ) {
			action = RESUBMIT;
		}
		break;
	case -EPIPE:
	case -EOVERFLOW:
		WLAN_LOG_WARNING("%s rx pipe stalled: requesting reset\n",
		                 wlandev->netdev->name);
		if ( !test_and_set_bit(WORK_RX_HALT, &hw->work_flags) )
			schedule_work(&hw->usb_work);
		action = ABORT;
		break;
	case -EILSEQ:
	case -ENODEV:
	case -ETIMEDOUT:
		WLAN_LOG_DEBUG(3,"status=%d, device removed.\n", urb->status);
		action = ABORT;
		break;
	case -ENOENT:
		WLAN_LOG_DEBUG(3,"status=%d, urb explicitly unlinked.\n", urb->status);
		action = ABORT;
		break;
	default:
		WLAN_LOG_DEBUG(3,"urb status=%d, transfer flags=0x%x\n",
		                 urb->status, urb->transfer_flags);
		action = RESUBMIT;
		break;
	}

	urb_status = urb->status;

	if (action != ABORT) {
		/* Repost the RX URB */
		result = submit_rx_urb(hw, GFP_ATOMIC);
		
		if (result != 0) {
			WLAN_LOG_ERROR(
				"Fatal, failed to resubmit rx_urb. error=%d\n",
				result);
		}
	}

	/* Handle any USB-IN packet */
	/* Note: the check of the sw_support field, the type field doesn't 
	 *       have bit 12 set like the docs suggest. 
	 */
	type = hfa384x2host_16(usbin->type);
	if (HFA384x_USB_ISRXFRM(type)) {
		if (action == HANDLE) {
			if (usbin->txfrm.desc.sw_support == 0x0123)
				hfa384x_usbin_txcompl(wlandev, usbin);
			else 
				hfa384x_usbin_rx(wlandev, usbin);
		}
		goto exit;
	}
	if (HFA384x_USB_ISTXFRM(type)) {
		if (action == HANDLE)
			hfa384x_usbin_txcompl(wlandev, usbin);
		goto exit;
	}
	switch (type) {
	case HFA384x_USB_INFOFRM:
		if (action == ABORT)
			goto exit;
		if (action == HANDLE)
			hfa384x_usbin_info(wlandev, usbin);
		break;
	case HFA384x_USB_CMDRESP:
	case HFA384x_USB_WRIDRESP:
	case HFA384x_USB_RRIDRESP:
	case HFA384x_USB_WMEMRESP:
	case HFA384x_USB_RMEMRESP:
		/* ALWAYS, ALWAYS, ALWAYS handle this CTLX!!!! */
		hfa384x_usbin_ctlx(wlandev, usbin, urb_status);
		break;
	case HFA384x_USB_BUFAVAIL:
		WLAN_LOG_DEBUG(3,"Received BUFAVAIL packet, frmlen=%d\n",
			usbin->bufavail.frmlen);
		break;

	case HFA384x_USB_ERROR:
		WLAN_LOG_DEBUG(3,"Received USB_ERROR packet, errortype=%d\n",
			usbin->usberror.errortype);
		break;

	default:
		WLAN_LOG_DEBUG(3,"Unrecognized USBIN packet, type=%x\n", 
			usbin->type);
		break;
	} /* switch */

exit:
	if (usbin)
		kfree(usbin);
	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_usbin_ctlx
*
* We've received a URB containing a Prism2 "response" message.
* This message needs to be matched up with a CTLX on the active
* queue and our state updated accordingly.
*
* Arguments:
*	wlandev		wlan device
*	urb		ptr to the URB
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_ctlx(wlandevice_t *wlandev, hfa384x_usbin_t *usbin, 
			int urb_status)
{
	hfa384x_t		*hw;
	hfa384x_usbctlx_t	*ctlx = NULL;
	CTLX_STATE		state = CTLX_START; /* will clobber later */
	unsigned long		flags;

	DBFENTER;

	if (!wlandev)
		goto done;

	hw = wlandev->priv;

	/* Search the active queue for the CTLX that requested this URB */
	spin_lock_irqsave(&hw->ctlxq.lock, flags);
	if ( !hw->usb_removed ) {
		struct list_head *item;

		list_for_each(item, &hw->ctlxq.active) {
			hfa384x_usbctlx_t	*c;

			c = list_entry(item, hfa384x_usbctlx_t, list);
			if (c->outbuf.type == (usbin->type&~host2hfa384x_16(0x8000))) {
				ctlx = c;
				state = ctlx->state;
				break;
			}
		}
	}

	/* If the queue is empty or we couldn't match the URB
	 * then there's nothing to do except try to run another
	 * pending command (if there is one) */
	if ( ctlx == NULL ) {
		spin_unlock_irqrestore(&hw->ctlxq.lock, flags);
		WLAN_LOG_WARNING("Could not match IN URB(0x%x,%d) to CTLX - ignored\n",
		                 usbin->type, urb_status);
		hfa384x_usbctlxq_run(&hw->ctlxq);
		goto done;
	}

	/* We have received a response URB for our CTLX,
	 * so we don't need the timeout any more ...
	 */
	del_timer(&ctlx->resptimer);

	switch ( state ) {
	case CTLX_REQ_SUBMITTED:
		/* We have received our response URB before
		 * our request has been acknowledged. Do NOT
		 * destroy our CTLX yet, because our OUT URB
		 * is still alive ...
		 */
		ctlx->state = CTLX_RESP_COMPLETE;
		spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

		if (urb_status != 0) {
			/* Cancel the request URB, because its
			 * response URB has failed.
			 */
			hfa384x_usbctlx_cancel_async(ctlx);
		}
		else {
			/* Copy the buffer to ctlx */
			memcpy(&ctlx->inbuf, usbin, sizeof(ctlx->inbuf));
		}

		/* Let the machine continue running. */
		break;

	case CTLX_REQ_COMPLETE:
		/* This is the usual path: our request
		 * has already been acknowledged, and
		 * we have now received the reply.
		 */
		ctlx->state = CTLX_COMPLETE;
		spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

		/* Copy the buffer to ctlx */
		if (urb_status == 0)
			memcpy(&ctlx->inbuf, usbin, sizeof(ctlx->inbuf));

		/* Call the completion handler and run the next command */
		hfa384x_usbctlx_complete(ctlx);
		hfa384x_usbctlxq_run(&hw->ctlxq);
		break;

	default:
		spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

		/* Throw this CTLX away. If it was running at
		 * the time then it will automatically run the
		 * next CTLX off the queue during its URB
		 * completion handler.
		 */
		hfa384x_usbctlx_cancel_async(ctlx);

		WLAN_LOG_WARNING(
			"Matched IN URB, CTLX in invalid state(0x%x). "
			"Discarded.\n", state);

		break;
	} /* switch */

done:
	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_usbin_txcompl
*
* At this point we have the results of a previous transmit.
*
* Arguments:
*	wlandev		wlan device
*	usbin		ptr to the usb transfer buffer
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_txcompl(wlandevice_t *wlandev, hfa384x_usbin_t *usbin)
{
	UINT16			status;
	DBFENTER;

	status = hfa384x2host_16(usbin->type); /* yeah I know it says type...*/

	/* Was there an error? */
	if (HFA384x_TXSTATUS_ISERROR(status)) {
		prism2sta_ev_txexc(wlandev, status);
	} else {
		prism2sta_ev_tx(wlandev, status);
	}
	// prism2sta_ev_alloc(wlandev);

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbin_rx
*
* At this point we have a successful received a rx frame packet.
*
* Arguments:
*	wlandev		wlan device
*	usbin		ptr to the usb transfer buffer
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_rx(wlandevice_t *wlandev, hfa384x_usbin_t *usbin)
{
	p80211_hdr_t            *w_hdr;
	struct sk_buff          *skb = NULL;
	int                     hdrlen;
	p80211_rxmeta_t	*rxmeta;
	UINT16                  fc;
	UINT8 *datap;

	DBFENTER;

	/* Byte order convert once up front. */
	usbin->rxfrm.desc.status =
		hfa384x2host_16(usbin->rxfrm.desc.status);
	usbin->rxfrm.desc.time =
		hfa384x2host_32(usbin->rxfrm.desc.time);

	/* Now handle frame based on port# */
        switch( HFA384x_RXSTATUS_MACPORT_GET(usbin->rxfrm.desc.status))
        {
	case 0:
		w_hdr = (p80211_hdr_t *) &(usbin->rxfrm.desc.frame_control);
		fc = ieee2host16(usbin->rxfrm.desc.frame_control);

		/* If exclude and we receive an unencrypted, drop it */
		if ( (wlandev->hostwep & HOSTWEP_EXCLUDEUNENCRYPTED) &&
		     !WLAN_GET_FC_ISWEP(fc)){
			goto done;
		}

		hdrlen = p80211_headerlen(fc);

		/* Allocate the buffer, note CRC (aka FCS). pballoc */
		/* assumes there needs to be space for one */
		skb = dev_alloc_skb(hfa384x2host_16(usbin->rxfrm.desc.data_len) + hdrlen + WLAN_CRC_LEN + 2); /* a litlte extra */

		if ( ! skb ) {
			WLAN_LOG_DEBUG(1, "alloc_skb failed.\n");
			goto done;
                }

		skb->dev = wlandev->netdev;
		skb->dev->last_rx = jiffies;

		/* theoretically align the IP header on a 32-bit word. */
		if ( hdrlen == WLAN_HDR_A4_LEN )
			skb_reserve(skb, 2);

		/* Copy the 802.11 hdr to the buffer */
		datap = skb_put(skb, WLAN_HDR_A3_LEN);
		memcpy(datap, w_hdr, WLAN_HDR_A3_LEN);

		/* Snag the A4 address if present */
		if (hdrlen == WLAN_HDR_A4_LEN) {
			datap = skb_put(skb, WLAN_ADDR_LEN);
			memcpy(datap, &usbin->rxfrm.desc.address4, WLAN_HDR_A3_LEN);
		}

		/* we can convert the data_len as we passed the original on */
		usbin->rxfrm.desc.data_len = hfa384x2host_16(usbin->rxfrm.desc.data_len);

		/* Copy the payload data to the buffer */
		if ( usbin->rxfrm.desc.data_len > 0 ) {
			datap = skb_put(skb, usbin->rxfrm.desc.data_len);
			memcpy(datap, &(usbin->rxfrm.data),  
				usbin->rxfrm.desc.data_len);
		}

		/* the prism2 series does not return the CRC */
		datap = skb_put(skb, WLAN_CRC_LEN);
		memset (datap, 0xff, WLAN_CRC_LEN);
		skb->mac.raw = skb->data;

		/* Attach the rxmeta, set some stuff */
		p80211skb_rxmeta_attach(wlandev, skb);
		rxmeta = P80211SKB_RXMETA(skb);
		rxmeta->mactime = usbin->rxfrm.desc.time;
		rxmeta->rxrate = usbin->rxfrm.desc.rate;
		rxmeta->signal = usbin->rxfrm.desc.signal;
		rxmeta->noise = usbin->rxfrm.desc.silence;

		prism2sta_ev_rx(wlandev, skb);

		break;

	case 7:
        	if ( ! HFA384x_RXSTATUS_ISFCSERR(usbin->rxfrm.desc.status) ) {
                        /* Copy to wlansnif skb */
                        hfa384x_int_rxmonitor( wlandev, &usbin->rxfrm);
                } else {
                        WLAN_LOG_DEBUG(3,"Received monitor frame: FCSerr set\n");
                }
                break;

	default:
		WLAN_LOG_WARNING("Received frame on unsupported port=%d\n",
			HFA384x_RXSTATUS_MACPORT_GET(usbin->rxfrm.desc.status) );
		goto done;
		break;
	}
	
done:
	DBFEXIT;
	return;
}

/*----------------------------------------------------------------
* hfa384x_int_rxmonitor
*
* Helper function for int_rx.  Handles monitor frames.
* Note that this function allocates space for the FCS and sets it
* to 0xffffffff.  The hfa384x doesn't give us the FCS value but the
* higher layers expect it.  0xffffffff is used as a flag to indicate
* the FCS is bogus.
*
* Arguments:
*	wlandev		wlan device structure
*	rxfrm		rx descriptor read from card in int_rx
*
* Returns: 
*	nothing
*
* Side effects:
*	Allocates an skb and passes it up via the PF_PACKET interface.
* Call context:
*	interrupt
----------------------------------------------------------------*/
static void hfa384x_int_rxmonitor( wlandevice_t *wlandev, hfa384x_usb_rxfrm_t *rxfrm)
{
	hfa384x_rx_frame_t              *rxdesc = &(rxfrm->desc);
	UINT				hdrlen = 0;
	UINT				datalen = 0;
	UINT				skblen = 0;
	p80211msg_lnxind_wlansniffrm_t	*msg;
	UINT8				*datap;
	UINT16				fc;
	struct sk_buff			*skb;
	hfa384x_t		        *hw = wlandev->priv;


	DBFENTER;
	/* Don't forget the status, time, and data_len fields are in host order */
	/* Figure out how big the frame is */
	fc = ieee2host16(rxdesc->frame_control);
	hdrlen = p80211_headerlen(fc);
	datalen = hfa384x2host_16(rxdesc->data_len);

	/* Allocate an ind message+framesize skb */
	skblen = sizeof(p80211msg_lnxind_wlansniffrm_t) + 
		hdrlen + datalen + WLAN_CRC_LEN;
	
	/* sanity check the length */
	if ( skblen > 
		(sizeof(p80211msg_lnxind_wlansniffrm_t) + 
		WLAN_HDR_A4_LEN + WLAN_DATA_MAXLEN + WLAN_CRC_LEN) ) {
		WLAN_LOG_DEBUG(1, "overlen frm: len=%d\n", 
			skblen - sizeof(p80211msg_lnxind_wlansniffrm_t));
	}
			
	if ( (skb = dev_alloc_skb(skblen)) == NULL ) {
		WLAN_LOG_ERROR("alloc_skb failed trying to allocate %d bytes\n", skblen);
		return;
	}

	/* only prepend the prism header if in the right mode */
	if ((wlandev->netdev->type == ARPHRD_IEEE80211_PRISM) &&
	    (hw->sniffhdr == 0)) {
		datap = skb_put(skb, sizeof(p80211msg_lnxind_wlansniffrm_t));
		msg = (p80211msg_lnxind_wlansniffrm_t*) datap;
	  
		/* Initialize the message members */
		msg->msgcode = DIDmsg_lnxind_wlansniffrm;
		msg->msglen = sizeof(p80211msg_lnxind_wlansniffrm_t);
		strcpy(msg->devname, wlandev->name);
		
		msg->hosttime.did = DIDmsg_lnxind_wlansniffrm_hosttime;
		msg->hosttime.status = 0;
		msg->hosttime.len = 4;
		msg->hosttime.data = jiffies;
		
		msg->mactime.did = DIDmsg_lnxind_wlansniffrm_mactime;
		msg->mactime.status = 0;
		msg->mactime.len = 4;
		msg->mactime.data = rxdesc->time;
		
		msg->channel.did = DIDmsg_lnxind_wlansniffrm_channel;
		msg->channel.status = 0;
		msg->channel.len = 4;
		msg->channel.data = hw->sniff_channel;
		
		msg->rssi.did = DIDmsg_lnxind_wlansniffrm_rssi;
		msg->rssi.status = P80211ENUM_msgitem_status_no_value;
		msg->rssi.len = 4;
		msg->rssi.data = 0;
		
		msg->sq.did = DIDmsg_lnxind_wlansniffrm_sq;
		msg->sq.status = P80211ENUM_msgitem_status_no_value;
		msg->sq.len = 4;
		msg->sq.data = 0;
		
		msg->signal.did = DIDmsg_lnxind_wlansniffrm_signal;
		msg->signal.status = 0;
		msg->signal.len = 4;
		msg->signal.data = rxdesc->signal;
		
		msg->noise.did = DIDmsg_lnxind_wlansniffrm_noise;
		msg->noise.status = 0;
		msg->noise.len = 4;
		msg->noise.data = rxdesc->silence;
		
		msg->rate.did = DIDmsg_lnxind_wlansniffrm_rate;
		msg->rate.status = 0;
		msg->rate.len = 4;
		msg->rate.data = rxdesc->rate / 5; /* set to 802.11 units */
		
		msg->istx.did = DIDmsg_lnxind_wlansniffrm_istx;
		msg->istx.status = 0;
		msg->istx.len = 4;
		msg->istx.data = P80211ENUM_truth_false;
		
		msg->frmlen.did = DIDmsg_lnxind_wlansniffrm_frmlen;
		msg->frmlen.status = 0;
		msg->frmlen.len = 4;
		msg->frmlen.data = hdrlen + datalen + WLAN_CRC_LEN;
	} else if ((wlandev->netdev->type == ARPHRD_IEEE80211_PRISM) &&
		   (hw->sniffhdr != 0)) {
		p80211_caphdr_t		*caphdr;
		/* The NEW header format! */
		datap = skb_put(skb, sizeof(p80211_caphdr_t));
		caphdr = (p80211_caphdr_t*) datap;

		caphdr->version =	htonl(P80211CAPTURE_VERSION);
		caphdr->length =	htonl(sizeof(p80211_caphdr_t));
		caphdr->mactime =	__cpu_to_be64(rxdesc->time) * 1000;
		caphdr->hosttime =	__cpu_to_be64(jiffies);
		caphdr->phytype =	htonl(4); /* dss_dot11_b */
		caphdr->channel =	htonl(hw->sniff_channel);
		caphdr->datarate =	htonl(rxdesc->rate);
		caphdr->antenna =	htonl(0); /* unknown */
		caphdr->priority =	htonl(0); /* unknown */
		caphdr->ssi_type =	htonl(3); /* rssi_raw */
		caphdr->ssi_signal =	htonl(rxdesc->signal);
		caphdr->ssi_noise =	htonl(rxdesc->silence);
		caphdr->preamble =	htonl(0); /* unknown */
		caphdr->encoding =	htonl(1); /* cck */
	}

	/* Copy the 802.11 header to the skb (ctl frames may be less than a full header) */
	datap = skb_put(skb, hdrlen);
	memcpy( datap, &(rxdesc->frame_control), hdrlen);

	/* If any, copy the data from the card to the skb */
	if ( datalen > 0 )
	{
		datap = skb_put(skb, datalen);
		memcpy(datap, rxfrm->data, datalen);

		/* check for unencrypted stuff if WEP bit set. */
		if (*(datap - hdrlen + 1) & 0x40) // wep set
		  if ((*(datap) == 0xaa) && (*(datap+1) == 0xaa))
		    *(datap - hdrlen + 1) &= 0xbf; // clear wep; it's the 802.2 header!
	}

	if (hw->sniff_fcs) {
		/* Set the FCS */
		datap = skb_put(skb, WLAN_CRC_LEN);
		memset( datap, 0xff, WLAN_CRC_LEN);
	}

	/* pass it back up */
	prism2sta_ev_rx(wlandev, skb);

	DBFEXIT;
	return;
}



/*----------------------------------------------------------------
* hfa384x_usbin_info
*
* At this point we have a successful received a Prism2 info frame.
*
* Arguments:
*	wlandev		wlan device
*	usbin		ptr to the usb transfer buffer
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_info(wlandevice_t *wlandev, hfa384x_usbin_t *usbin)
{
	DBFENTER;

	usbin->infofrm.info.framelen = hfa384x2host_16(usbin->infofrm.info.framelen);
	prism2sta_ev_info(wlandev, &usbin->infofrm.info);

	DBFEXIT;
}



/*----------------------------------------------------------------
* hfa384x_usbout_callback
*
* Callback for URBs on the BULKOUT endpoint.
*
* Arguments:
*	urb		ptr to the completed urb
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
void hfa384x_usbout_callback(struct urb *urb)
#else
void hfa384x_usbout_callback(struct urb *urb, struct pt_regs *regs)
#endif
{
	wlandevice_t		*wlandev = urb->context;
	hfa384x_usbout_t	*usbout = urb->transfer_buffer;
	DBFENTER;

#ifdef DEBUG_USB
	dbprint_urb(urb);
#endif

	if ( wlandev &&
	     wlandev->netdev ) {

		switch(urb->status) {
		case 0:
			hfa384x_usbout_tx(wlandev, usbout);
			break;
		case -EPIPE:
		{
			hfa384x_t *hw = wlandev->priv;
			WLAN_LOG_WARNING("%s tx pipe stalled: requesting reset\n",
			                 wlandev->netdev->name);
			if ( !test_and_set_bit(WORK_TX_HALT, &hw->work_flags) )
				schedule_work(&hw->usb_work);
			break;
		}
		case -ENOENT:
			/* Ignorable error */
			break;
		default:
			WLAN_LOG_INFO("unknown urb->status=%d\n", urb->status);
			break;
		} /* switch */
	}

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_ctlxout_callback
*
* Callback for control data on the BULKOUT endpoint.
*
* Arguments:
*	urb		ptr to the completed urb
*
* Returns:
* nothing
*
* Side effects:
*
* Call context:
* interrupt
----------------------------------------------------------------*/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
void hfa384x_ctlxout_callback(struct urb *urb)
#else
void hfa384x_ctlxout_callback(struct urb *urb, struct pt_regs *regs)
#endif
{
	hfa384x_usbctlx_t	*ctlx = urb->context;
	hfa384x_t		*hw = ctlx->hw;
	CTLX_STATE		state;
	unsigned long		flags;
	DBFENTER;

	WLAN_LOG_DEBUG(3,"urb->status=%d\n", urb->status);
#ifdef DEBUG_USB
	dbprint_urb(urb);
#endif
	if (ctlx == NULL)
		goto done;

	spin_lock_irqsave(&hw->ctlxq.lock, flags);

	/* We can safely delete a timer even when it has expired */
	del_timer(&ctlx->reqtimer);

	state = ctlx->state;

	if ( urb->status == 0 ) {
		/* Request portion of a CTLX is successful */
		switch ( state ) {
		case CTLX_REQ_SUBMITTED:
			/* This OUT-ACK received before IN */
			ctlx->state = CTLX_REQ_COMPLETE;

			spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

			/* Machine continues while we wait for this 
			 * CTLX's reply URB to arrive ...
			 */
			break;

		case CTLX_RESP_COMPLETE:
			/* IN already received before this OUT-ACK,
			 * so this command must now be complete.
			 */
			ctlx->state = CTLX_COMPLETE;

			spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

			/* Call the completion handler */
			hfa384x_usbctlx_complete(ctlx);
			hfa384x_usbctlxq_run(&hw->ctlxq);
			break;

		default:
			spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

			/* This is NOT a valid CTLX "success" state! */
			WLAN_LOG_ERROR(
			    "Illegal CTLX success state(0x%x, %d) in OUT URB\n",
			    state, urb->status);
			break;
		} /* switch */
	} else {
		/* If the pipe has stalled then we need to reset it */
		if ( (urb->status == -EPIPE) &&
		      !test_and_set_bit(WORK_TX_HALT, &hw->work_flags) ) {
			WLAN_LOG_WARNING("%s tx pipe stalled: requesting reset\n",
			                 hw->wlandev->netdev->name);
			schedule_work(&hw->usb_work);
		}

		/* If someone cancels the OUT URB then its status
		 * should be either -ECONNRESET or -ENOENT.
		 */
		switch ( state ) {
		case CTLX_REQ_SUBMITTED:
			/* OUT packet has failed, so we're
			 * not going to wait for a response.
			 */
			del_timer(&ctlx->resptimer);
			/* fall through */

		case CTLX_RESP_COMPLETE:
			/* The response returned with an
			 * error before the request packet
			 * was acknowledged.
			 *
			 * This request has failed, so this
			 * CTLX must now be cleaned up.
			 */
			ctlx->state = CTLX_REQ_FAILED;
			/* fall through */

		case CTLX_REQ_FAILED:
		case CTLX_REQ_TIMEOUT:
			/* These mean that either the CTLX OUT
			 * URB timed out, or we cancelled the
			 * entire CTLX.
			 */
			spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

			hfa384x_usbctlx_complete(ctlx);
			hfa384x_usbctlxq_run(&hw->ctlxq);
			break;

		default:
			spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

			/* This is not a valid CTLX "error" state */
			WLAN_LOG_ERROR(
			    "Illegal CTLX error state(0x%x, %d) in OUT URB\n",
			    state, urb->status);
			break;
		} /* switch */
	}

done:
	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_reqtimerfn
*
* Timer response function for CTLX request timeouts.  If this 
* function is called, it means that the callback for the OUT
* URB containing a Prism2.x XXX_Request was never called.
*
* Arguments:
*	data		a ptr to the ctlx
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_usbctlx_reqtimerfn(unsigned long data)
{
	hfa384x_usbctlx_t	*ctlx = (hfa384x_usbctlx_t*)data;
	hfa384x_t		*hw = ctlx->hw;
	unsigned long		flags;

	DBFENTER;

	spin_lock_irqsave(&hw->ctlxq.lock, flags);

	/* We must ensure that our URB is removed from
	 * the system, if it hasn't already expired.
	 */
	ctlx->outurb.transfer_flags |= URB_ASYNC_UNLINK;
	if (usb_unlink_urb(&ctlx->outurb) == -EINPROGRESS) {

		/* We are cancelling this CTLX, so we're
		 * not going to need to wait for a response.
		 */
		del_timer(&ctlx->resptimer);

		/* This URB was active, but has now been
		 * cancelled. It will now have a status of
		 * -ECONNRESET in the callback function.
		 */
		ctlx->state = CTLX_REQ_TIMEOUT;
	}

	spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_resptimerfn
*
* Timer response function for CTLX response timeouts.  If this 
* function is called, it means that the callback for the IN
* URB containing a Prism2.x XXX_Response was never called.
*
* Arguments:
*	data		a ptr to the ctlx
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_usbctlx_resptimerfn(unsigned long data)
{
	hfa384x_usbctlx_t	*ctlx = (hfa384x_usbctlx_t*)data;

	DBFENTER;

	hfa384x_usbctlx_cancel_async(ctlx);

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_submit_async
*
* Called from the doxxx functions to do an async submit of a
* CTLX.
*
* Arguments:
*	hw		ptr to the hw struct
*	ctlx		ctlx structure to enqueue		
*
* Returns: 
*	0       - command queued
*	-ENODEV - command not queued.
*
* Side effects:
*
* Call context:
*	interrupt or process
----------------------------------------------------------------*/
int
hfa384x_usbctlx_submit_async(
	hfa384x_t		*hw, 
	hfa384x_usbctlx_t	*ctlx,
	ctlx_usercb_t		usercb,
	void			*usercb_data)
{
	int result = -ENODEV;
	DBFENTER;

	if (hw) {
		/* fill usercb and data */
		ctlx->usercb = usercb;
		ctlx->usercb_data = usercb_data;

		/* set isasync */
		ctlx->is_async = 1;

		/* enqueue_run */
		result = hfa384x_usbctlxq_enqueue_run(&hw->ctlxq, ctlx);
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_submit_wait
*
* Called from the doxxx functions to do a blocking submit of a
* CTLX.
*
* Arguments:
*	hw		ptr to the hw struct
*	ctlx		ctlx structure to enqueue		
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
void 
hfa384x_usbctlx_submit_wait(
	hfa384x_t		*hw, 
	hfa384x_usbctlx_t	*ctlx)
{
	DBFENTER;

	if (!hw || !hw->wlandev)
		return;

	ctlx->wanna_wakeup = 0;

	/* Put the new command on the queue, and kick-start the queue */
	if (hfa384x_usbctlxq_enqueue_run(&hw->ctlxq, ctlx) == 0) {

		WLAN_LOG_DEBUG(3,"Sleeping...\n");
		if (in_interrupt() || in_atomic()) {
			WLAN_LOG_DEBUG(1,"** WLAN busy-sleeping in interrupt context!\n");
			while(!ctlx->wanna_wakeup)
				udelay(1000);
		} else if ( wait_event_interruptible(hw->cmdq, ctlx->wanna_wakeup) ) {
			/* We must have been interrupted, so cancel this
			 * command and start the next one ...
			 */
			hfa384x_usbctlx_cancel(ctlx);
			hfa384x_usbctlxq_run(&hw->ctlxq);
		}
	}
	
	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_usbout_tx
*
* At this point we have finished a send of a frame.  Mark the URB
* as available and call ev_alloc to notify higher layers we're
* ready for more.
*
* Arguments:
*	wlandev		wlan device
*	usbout		ptr to the usb transfer buffer
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbout_tx(wlandevice_t *wlandev, hfa384x_usbout_t *usbout)
{
	DBFENTER;

	prism2sta_ev_alloc(wlandev);
	
	DBFEXIT;
}

/*----------------------------------------------------------------
* hfa384x_isgood_pdrcore
*
* Quick check of PDR codes.
*
* Arguments:
*	pdrcode		PDR code number (host order)
*
* Returns: 
*	zero		not good.
*	one		is good.
*
* Side effects:
*
* Call context:
----------------------------------------------------------------*/
int
hfa384x_isgood_pdrcode(UINT16 pdrcode)
{
	switch(pdrcode) {
	case HFA384x_PDR_END_OF_PDA:
	case HFA384x_PDR_PCB_PARTNUM:
	case HFA384x_PDR_PDAVER:
	case HFA384x_PDR_NIC_SERIAL:
	case HFA384x_PDR_MKK_MEASUREMENTS:
	case HFA384x_PDR_NIC_RAMSIZE:
	case HFA384x_PDR_MFISUPRANGE:
	case HFA384x_PDR_CFISUPRANGE:
	case HFA384x_PDR_NICID:
	case HFA384x_PDR_MAC_ADDRESS:
	case HFA384x_PDR_REGDOMAIN:
	case HFA384x_PDR_ALLOWED_CHANNEL:
	case HFA384x_PDR_DEFAULT_CHANNEL:
	case HFA384x_PDR_TEMPTYPE:
	case HFA384x_PDR_IFR_SETTING:
	case HFA384x_PDR_RFR_SETTING:
	case HFA384x_PDR_HFA3861_BASELINE:
	case HFA384x_PDR_HFA3861_SHADOW:
	case HFA384x_PDR_HFA3861_IFRF:
	case HFA384x_PDR_HFA3861_CHCALSP:
	case HFA384x_PDR_HFA3861_CHCALI:
	case HFA384x_PDR_3842_NIC_CONFIG:
	case HFA384x_PDR_USB_ID:
	case HFA384x_PDR_PCI_ID:
	case HFA384x_PDR_PCI_IFCONF:
	case HFA384x_PDR_PCI_PMCONF:
	case HFA384x_PDR_RFENRGY:
	case HFA384x_PDR_HFA3861_MANF_TESTSP:
	case HFA384x_PDR_HFA3861_MANF_TESTI:
		/* code is OK */
		return 1;
		break;
	default:
		if ( pdrcode < 0x1000 ) {
			/* code is OK, but we don't know exactly what it is */
			WLAN_LOG_DEBUG(3,
				"Encountered unknown PDR#=0x%04x, "
				"assuming it's ok.\n", 
				pdrcode);
			return 1;
		} else {
			/* bad code */
			WLAN_LOG_DEBUG(3,
				"Encountered unknown PDR#=0x%04x, "
				"(>=0x1000), assuming it's bad.\n",
				pdrcode);
			return 0;
		}
		break;
	}
	return 0; /* avoid compiler warnings */
}

