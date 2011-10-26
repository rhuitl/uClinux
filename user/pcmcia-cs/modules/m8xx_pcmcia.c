/* 
 * m8xx_pcmcia.c - Linux PCMCIA socket driver for the mpc8xx series.
 *
 * (C) 1999-2000 Magnus Damm <damm@bitsmart.com>
 *
 * "The ExCA standard specifies that socket controllers should provide 
 * two IO and five memory windows per socket, which can be independently 
 * configured and positioned in the host address space and mapped to 
 * arbitrary segments of card address space. " - David A Hinds. 1999
 *
 * This controller does _not_ meet the ExCA standard.
 * 
 * m8xx pcmcia controller brief info:
 * + 8 windows (attrib, mem, i/o)
 * + up to two slots (SLOT_A and SLOT_B)
 * + inputpins, outputpins, event and mask registers.
 * - no offset register. sigh.
 *
 * Because of the lacking offset register we must map the whole card.
 * We assign each memory window PCMCIA_MEM_WIN_SIZE address space.
 * Make sure there is (PCMCIA_MEM_WIN_SIZE * PCMCIA_MEM_WIN_NO 
 * * PCMCIA_SOCKETS_NO) bytes at PCMCIA_MEM_WIN_BASE.
 * The i/o windows are dynamically allocated at PCMCIA_IO_WIN_BASE.
 * They are maximum 64KByte each...
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/string.h>

#include <asm/io.h>
#include <asm/bitops.h>
#include <asm/segment.h>
#include <asm/system.h>

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/malloc.h>
#include <linux/timer.h>
#include <linux/ioport.h>
#include <linux/delay.h>

#include <asm/mpc8xx.h>
#include <asm/8xx_immap.h>
#include <asm/irq.h>

#include <pcmcia/version.h>
#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/ss.h>

#ifdef PCMCIA_DEBUG
static int pc_debug = PCMCIA_DEBUG;
MODULE_PARM(pc_debug, "i");
#define DEBUG(n, args...) printk(KERN_DEBUG "m8xx_pcmcia: " args);
#else
#define DEBUG(n, args...)
#endif

#define PCMCIA_INFO(args...) printk(KERN_INFO "m8xx_pcmcia: "args)
#define PCMCIA_ERROR(args...) printk(KERN_ERR "m8xx_pcmcia: "args)

static const char *version = "Version 0.03, 14-Feb-2000, Magnus Damm";

/* ------------------------------------------------------------------------- */
/* Autoconfigure boards if no settings are defined                           */
 
#if !defined(CONFIG_PCMCIA_SLOT_A) && !defined(CONFIG_PCMCIA_SLOT_B)

/* The RPX series use SLOT_B */

#if defined(CONFIG_RPXCLASSIC) || defined(CONFIG_RPXLITE)
#define CONFIG_PCMCIA_SLOT_B
#define CONFIG_BD_IS_MHZ
#endif

/* The ADS board use SLOT_A */

#ifdef CONFIG_ADS
#define CONFIG_PCMCIA_SLOT_A
#define CONFIG_BD_IS_MHZ
#endif

/* The FADS series are a mess */

#ifdef CONFIG_FADS
#if defined(CONFIG_MPC860T) || defined(CONFIG_MPC860) || defined(CONFIG_MPC821)
#define CONFIG_PCMCIA_SLOT_A
#else
#define CONFIG_PCMCIA_SLOT_B
#endif
#endif

#endif /* !defined(CONFIG_PCMCIA_SLOT_A) && !defined(CONFIG_PCMCIA_SLOT_B) */

/* ------------------------------------------------------------------------- */

#define PCMCIA_MEM_WIN_BASE 0xe0000000 /* base address for memory window 0   */
#define PCMCIA_MEM_WIN_SIZE 0x04000000 /* each memory window is 64 MByte     */
#define PCMCIA_IO_WIN_BASE  _IO_BASE   /* base address for io window 0       */

#define PCMCIA_SCHLVL PCMCIA_INTERRUPT /* Status Change Interrupt Level      */

/* ------------------------------------------------------------------------- */

#if defined(CONFIG_PCMCIA_SLOT_A) && defined(CONFIG_PCMCIA_SLOT_B)

#define PCMCIA_SOCKETS_NO 2  

/* We have only 8 windows, dualsocket support will be limited. */

#define PCMCIA_MEM_WIN_NO 2
#define PCMCIA_IO_WIN_NO  2
#define PCMCIA_SLOT_MSG "SLOT_A and SLOT_B"

#elif defined(CONFIG_PCMCIA_SLOT_A) || defined(CONFIG_PCMCIA_SLOT_B)

#define PCMCIA_SOCKETS_NO 1

#define PCMCIA_MEM_WIN_NO 5
#define PCMCIA_IO_WIN_NO  2

/* define _slot_ to be able to optimize macros */

#ifdef CONFIG_PCMCIA_SLOT_A
#define _slot_ 0
#define PCMCIA_SLOT_MSG "SLOT_A"
#else
#define _slot_ 1
#define PCMCIA_SLOT_MSG "SLOT_B"
#endif

#else
#error m8xx_pcmcia: Bad configuration!
#endif

#ifdef CONFIG_BD_IS_MHZ
#ifdef CONFIG_CPU_PPC_8xx
#define M8XX_BUSFREQ ((((bd_t *)&(__res))->bi_busfreq) * 1000000)
#else
#define M8XX_BUSFREQ ((mpc8xx_bdinfo->bi_busfreq) * 1000000)
#endif
#else
#ifdef CONFIG_CPU_PPC_8xx
#define M8XX_BUSFREQ ((((bd_t *)&(__res))->bi_busfreq))
#else
#define M8XX_BUSFREQ (mpc8xx_bdinfo->bi_busfreq)
#endif
#endif

static int pcmcia_schlvl = PCMCIA_SCHLVL;

/* ------------------------------------------------------------------------- */

#define PCMCIA_SOCKET_KEY_5V 1
#define PCMCIA_SOCKET_KEY_LV 2


/* look up table for pgcrx registers */

static u_int *m8xx_pgcrx[2] = {
	&((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pgcra,
	&((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pgcrb
}; 

/*
 * This structure is used to address each window in the PCMCIA controller. 
 * 
 * Keep in mind that we assume that pcmcia_win_t[n+1] is mapped directly
 * after pcmcia_win_t[n]... 
 */

typedef struct {             
	uint	br;           
	uint	or;
} pcmcia_win_t;

/* 
 * For some reason the hardware guys decided to make both slots share
 * some registers.
 *
 * Could someone invent object oriented hardware ?
 *
 * The macros are used to get the right bit from the registers.
 * SLOT_A : slot = 0
 * SLOT_B : slot = 1
 */

#define M8XX_PCMCIA_VS1(slot)      (0x80000000 >> (slot << 4))
#define M8XX_PCMCIA_VS2(slot)      (0x40000000 >> (slot << 4))
#define M8XX_PCMCIA_VS_MASK(slot)  (0xc0000000 >> (slot << 4))
#define M8XX_PCMCIA_VS_SHIFT(slot) (30 - (slot << 4))

#define M8XX_PCMCIA_WP(slot)       (0x20000000 >> (slot << 4))
#define M8XX_PCMCIA_CD2(slot)      (0x10000000 >> (slot << 4))
#define M8XX_PCMCIA_CD1(slot)      (0x08000000 >> (slot << 4))
#define M8XX_PCMCIA_BVD2(slot)     (0x04000000 >> (slot << 4))
#define M8XX_PCMCIA_BVD1(slot)     (0x02000000 >> (slot << 4))
#define M8XX_PCMCIA_RDY(slot)      (0x01000000 >> (slot << 4))
#define M8XX_PCMCIA_RDY_L(slot)    (0x00800000 >> (slot << 4))
#define M8XX_PCMCIA_RDY_H(slot)    (0x00400000 >> (slot << 4))
#define M8XX_PCMCIA_RDY_R(slot)    (0x00200000 >> (slot << 4))
#define M8XX_PCMCIA_RDY_F(slot)    (0x00100000 >> (slot << 4))
#define M8XX_PCMCIA_MASK(slot)     (0xFFFF0000 >> (slot << 4))

#define M8XX_PGCRX(slot)  (*m8xx_pgcrx[slot])

#define M8XX_PGCRX_CXOE    0x00000080
#define M8XX_PGCRX_CXRESET 0x00000040

/* we keep one lookup table per socket to check flags */ 

#define PCMCIA_EVENTS_MAX 5  /* 4 max at a time + termination */

typedef struct  {
	u_int regbit;
	u_int eventbit;
} event_table_t;

typedef struct socket_info_t {
    void	(*handler)(void *info, u_int events);
    void	*info;

    u_int  slot;

    socket_state_t state;
    struct pccard_mem_map mem_win[PCMCIA_MEM_WIN_NO];
    struct pccard_io_map  io_win[PCMCIA_IO_WIN_NO];
    event_table_t events[PCMCIA_EVENTS_MAX]; 
} socket_info_t;

static socket_info_t socket[PCMCIA_SOCKETS_NO];

static socket_cap_t capabilities = {
    /* only 16-bit cards, memory windows must be size-aligned */
    SS_CAP_PCCARD | SS_CAP_MEM_ALIGN | SS_CAP_STATIC_MAP,
    0x000,		/* SIU_LEVEL 7 -> 0          */
    0x1000,		/* 4K minimum window size    */
    9, 0		/* No PCI or CardBus support */
};

/* 
 * Search this table to see if the windowsize is
 * supported...
 */

#define M8XX_SIZES_NO 32

static const u_int m8xx_size_to_gray[M8XX_SIZES_NO] = 
{ 0x00000001, 0x00000002, 0x00000008, 0x00000004,
  0x00000080, 0x00000040, 0x00000010, 0x00000020,
  0x00008000, 0x00004000, 0x00001000, 0x00002000,
  0x00000100, 0x00000200, 0x00000800, 0x00000400,

  0x0fffffff, 0xffffffff, 0xffffffff, 0xffffffff,
  0x01000000, 0x02000000, 0xffffffff, 0x04000000,
  0x00010000, 0x00020000, 0x00080000, 0x00040000,
  0x00800000, 0x00400000, 0x00100000, 0x00200000 };


/* ------------------------------------------------------------------------- */

static void m8xx_interrupt(int irq, void *dev, struct pt_regs *regs);
static int m8xx_service(u_int sock, u_int cmd, void *arg);

#define PCMCIA_BMT_LIMIT (15*4)  /* Bus Monitor Timeout value */

/* ------------------------------------------------------------------------- */
/* board specific stuff:                                                     */
/* voltage_set(), hardware_enable() and hardware_disable()                   */
/* ------------------------------------------------------------------------- */
/* RPX Boards from Embedded Planet                                           */

#if defined(CONFIG_RPXCLASSIC) || defined(CONFIG_RPXLITE)

/* The RPX boards seems to have it's bus monitor timeout set to 6*8 clocks.
 * SYPCR is write once only, therefore must the slowest memory be faster 
 * than the bus monitor or we will get a machine check due to the bus timeout.
 */

#define PCMCIA_BOARD_MSG "RPX CLASSIC or RPX LITE"

#undef PCMCIA_BMT_LIMIT
#define PCMCIA_BMT_LIMIT (6*8) 

static int voltage_set(int slot, int vcc, int vpp)
{
	u_int reg = 0;

	switch(vcc) {
	case 0: break;
	case 33: reg |= BCSR1_PCVCTL4; break;
	case 50: reg |= BCSR1_PCVCTL5; break;
	default: return 1;
	}

	switch(vpp) {
	case 0: break;
	case 33: 
	case 50:
		if(vcc == vpp)
			reg |= BCSR1_PCVCTL6;
		else
			return 1;
		break;
	case 120: 
		reg |= BCSR1_PCVCTL7;
	default: return 1;
	}

	if(!((vcc == 50) || (vcc == 0)))
	   return 1;

	/* first, turn off all power */

	*((uint *)RPX_CSR_ADDR) &= ~(BCSR1_PCVCTL4 | BCSR1_PCVCTL5
				     | BCSR1_PCVCTL6 | BCSR1_PCVCTL7);

	/* enable new powersettings */

	*((uint *)RPX_CSR_ADDR) |= reg;

	return 0;
}

#define socket_get(_slot_) PCMCIA_SOCKET_KEY_5V
#define hardware_enable(_slot_)  /* No hardware to enable */
#define hardware_disable(_slot_) /* No hardware to disable */

#endif /* CONFIG_RPXCLASSIC */

/* ------------------------------------------------------------------------- */
/* (F)ADS Boards from Motorola                                               */

#if defined(CONFIG_ADS) || defined(CONFIG_FADS)

#ifdef CONFIG_ADS
#define PCMCIA_BOARD_MSG "ADS"
#define PCMCIA_GLITCHY_CD  /* My ADS board needs this */
#else
#define PCMCIA_BOARD_MSG "FADS"
#endif

static int voltage_set(int slot, int vcc, int vpp)
{
	u_int reg = 0;
	
	switch(vpp) {
	case 0: reg = 0; break;
	case 50: reg = 1; break;
	case 120: reg = 2; break;
	default: return 1;
	}

	switch(vcc) {
	case 0: reg = 0; break;
#ifdef CONFIG_ADS
	case 50: reg = BCSR1_PCCVCCON; break;
#endif
#ifdef CONFIG_FADS
	case 33: reg = BCSR1_PCCVCC0 | BCSR1_PCCVCC1; break;
	case 50: reg = BCSR1_PCCVCC1; break;
#endif
	default: return 1;
	}

	/* first, turn off all power */

#ifdef CONFIG_ADS
	*((uint *)BCSR1) |= BCSR1_PCCVCCON;  
#endif
#ifdef CONFIG_FADS
	*((uint *)BCSR1) &= ~(BCSR1_PCCVCC0 | BCSR1_PCCVCC1);  
#endif
	*((uint *)BCSR1) &= ~BCSR1_PCCVPP_MASK;

	/* enable new powersettings */

#ifdef CONFIG_ADS
	*((uint *)BCSR1) &= ~reg;  
#endif
#ifdef CONFIG_FADS
	*((uint *)BCSR1) |= reg;  
#endif
	
 	*((uint *)BCSR1) |= reg << 20;
        
	return 0;
}

#define socket_get(_slot_) PCMCIA_SOCKET_KEY_5V

static void hardware_enable(int slot)
{
	*((uint *)BCSR1) &= ~BCSR1_PCCEN;
}

static void hardware_disable(int slot)
{
	*((uint *)BCSR1) &= ~BCSR1_PCCEN;
}

#endif

/* ------------------------------------------------------------------------- */

static void m8xx_shutdown(void)
{
	u_int k, m;
	pcmcia_win_t *w;

#if (PCMCIA_SOCKETS_NO == 2)
	u_int _slot_;
#endif    
	
	w = (void *) &((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pbr0;

	for(k = 0; k < PCMCIA_SOCKETS_NO; k++) {

#if (PCMCIA_SOCKETS_NO == 2)
		_slot_ = socket[k].slot;
#endif    

		((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pscr = 
			M8XX_PCMCIA_MASK(_slot_); 
		((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_per 
			&= ~M8XX_PCMCIA_MASK(_slot_);
 
		/* turn off interrupt and disable CxOE */

		M8XX_PGCRX(_slot_) = M8XX_PGCRX_CXOE;

		/* turn off memory windows */

		for(m = 0; m < PCMCIA_MEM_WIN_NO; m++) {
			w->or = 0;  /* set to not valid */
			w++;
		}

		/* turn off voltage */

		voltage_set(_slot_, 0, 0);

		/* disable external hardware */
	
		hardware_disable(_slot_);
	}

	free_irq(pcmcia_schlvl, NULL);

}

/* ------------------------------------------------------------------------- */

static int __init m8xx_init(void)
{
	servinfo_t serv;
	pcmcia_win_t *w;
	u_int k, m;

#if (PCMCIA_SOCKETS_NO == 2)
	u_int _slot_;
#endif    
	PCMCIA_INFO("%s\n", version);
	CardServices(GetCardServicesInfo, &serv);
	if (serv.Revision != CS_RELEASE_CODE) {
		PCMCIA_ERROR("Card Services release does not match!\n");
		return -1;
	}

	PCMCIA_INFO(PCMCIA_BOARD_MSG " using " PCMCIA_SLOT_MSG 
		    " with IRQ %u.\n", pcmcia_schlvl); 

	/* Configure Status change interrupt */

	if(request_8xxirq(pcmcia_schlvl, m8xx_interrupt, 0, 
			   "m8xx_pcmcia", NULL)) {
		PCMCIA_ERROR("Cannot allocate IRQ %u for SCHLVL!\n", 
			     pcmcia_schlvl);
		return -1;
	}

	w = (void *) &((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pbr0;

	for(k = 0; k < PCMCIA_SOCKETS_NO; k++) {

		/* Setup internal hardware */

#if (PCMCIA_SOCKETS_NO == 2)
		_slot_ = socket[k].slot = k;
#else
		socket[k].slot = _slot_;
#endif
	    
		((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pscr = 
			M8XX_PCMCIA_MASK(_slot_); 
		((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_per 
			&= ~M8XX_PCMCIA_MASK(_slot_);
 
		/* connect interrupt and disable CxOE */

		M8XX_PGCRX(_slot_) = M8XX_PGCRX_CXOE |
			(mk_int_int_mask(pcmcia_schlvl) << 16);

		/* intialize the fixed memory windows */

		for(m = 0; m < PCMCIA_MEM_WIN_NO; m++) {
			w->br = PCMCIA_MEM_WIN_BASE + 
				(PCMCIA_MEM_WIN_SIZE 
				 * (m + k * PCMCIA_MEM_WIN_NO));

			w->or = 0;  /* set to not valid */

			DEBUG(3,"Socket %u: MemWin %u: Base 0x%08x.\n",
			      k, m, w->br);

			w++;
		}


		/* turn off voltage */

		voltage_set(_slot_, 0, 0);

		/* Enable external hardware */
	    
		hardware_enable(_slot_);
	}

	if(register_ss_entry(PCMCIA_SOCKETS_NO, &m8xx_service) != 0) {
	    PCMCIA_ERROR("register_ss_entry() failed.\n");
	    m8xx_shutdown();
	    return -ENODEV;
	}

	return 0;
    
}

/* ------------------------------------------------------------------------- */

static void __exit m8xx_exit(void)
{
	unregister_ss_entry(&m8xx_service);

	m8xx_shutdown();
}

/* ------------------------------------------------------------------------- */

static void m8xx_interrupt(int irq, void *dev, struct pt_regs *regs)
{
	socket_info_t *s;
	event_table_t *e;
	u_int events, pscr, pipr, k;

#if (PCMCIA_SOCKETS_NO == 2)
	u_int _slot_;
#endif    
	DEBUG(3,"Interrupt!\n");

	/* get interrupt sources */

	pscr = ((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pscr;
	pipr = ((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pipr;

	s = &socket[0];

	for(k = 0; k < PCMCIA_SOCKETS_NO; k++) { 

	    if(s->handler) {

		    e = &s->events[0]; 
		    events = 0;
#if (PCMCIA_SOCKETS_NO == 2)
		    _slot_ = s->slot;
#endif    

		    while(e->regbit) {
			    if(pscr & e->regbit)
				    events |= e->eventbit;
		    
			    e++;
		    }

		    /* 
		     * report only if both card detect signals are the same 
		     * not too nice done, 
		     * we depend on that CD2 is the bit to the left of CD1...
		     */

		    if(events & SS_DETECT)
			    if(((pipr & M8XX_PCMCIA_CD2(_slot_)) >> 1)
				    ^ (pipr & M8XX_PCMCIA_CD1(_slot_)))
				    events &= ~SS_DETECT;

#ifdef PCMCIA_GLITCHY_CD
		    
		    /*
		     * I've experienced CD problems with my ADS board.
		     * We make an extra check to see if there was a
		     * real change of Card detection.
		     */

		    if((events & SS_DETECT) && 
		       ((pipr &
			 (M8XX_PCMCIA_CD2(_slot_) | M8XX_PCMCIA_CD1(_slot_)))
			== 0) && (s->state.Vcc | s->state.Vpp)) {
			  events &= ~SS_DETECT;
			  printk( "CD glitch workaround - CD = 0x%08x!\n",
				(pipr & (M8XX_PCMCIA_CD2(_slot_) 
					 | M8XX_PCMCIA_CD1(_slot_))));
		    }
#endif

		    /* call the handler */

		    DEBUG(3,"slot %u: events = 0x%02x, pscr = 0x%08x, "
			  "pipr = 0x%08x\n", 
			  _slot_, events, pscr, pipr);

		    if(events)
			    s->handler(s->info, events);

	    }

	    s++;
    }

    /* clear the interrupt sources */

    ((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pscr = pscr;
    
    DEBUG(3,"Interrupt done.\n");
    
}

/* ------------------------------------------------------------------------- */

static u_int m8xx_get_graycode(u_int size)
{
	u_int k;

	for(k = 0; k < M8XX_SIZES_NO; k++)
		if(m8xx_size_to_gray[k] == size)
			break;

	if((k == M8XX_SIZES_NO) || (m8xx_size_to_gray[k] == -1))
		k = -1;

	return k;
}

/* ------------------------------------------------------------------------- */

static u_int m8xx_get_speed(u_int ns, u_int is_io)
{
	u_int reg, clocks, psst, psl, psht;

	if(!ns) {

		/*
		 * We get called with IO maps setup to 0ns
		 * if not specified by the user.
		 * They should be 255ns.
		 */

		if(is_io)
			ns = 255;
		else 
			ns = 100;  /* fast memory if 0 */
	}

	/* 
	 * In PSST, PSL, PSHT fields we tell the controller
	 * timing parameters in CLKOUT clock cycles.
	 * CLKOUT is the same as GCLK2_50.
	 */

/* how we want to adjust the timing - in percent */

#define ADJ 180 /* 80 % longer accesstime - to be sure */


	clocks = ((M8XX_BUSFREQ / 1000) * ns) / 1000;
	clocks = (clocks * ADJ) / (100*1000);
	if(clocks >= PCMCIA_BMT_LIMIT) {
		printk( "Max access time limit reached\n");
		clocks = PCMCIA_BMT_LIMIT-1;
	}

	psst = clocks / 7;          /* setup time */
	psht = clocks / 7;          /* hold time */
	psl  = (clocks * 5) / 7;    /* strobe length */

	psst += clocks - (psst + psht + psl);

	reg =  psst << 12;
	reg |= psl  << 7; 
	reg |= psht << 16;

	return reg;
}

/* ------------------------------------------------------------------------- */
	
static int m8xx_register_callback(u_short lsock, ss_callback_t *call)
{
	if (call == NULL) {
		socket[lsock].handler = NULL;
		MOD_DEC_USE_COUNT;
	} 
	else {
		MOD_INC_USE_COUNT;
		socket[lsock].handler = call->handler;
		socket[lsock].info = call->info;
	}
	return 0;
}

/* ------------------------------------------------------------------------- */

static int m8xx_get_status(u_short lsock, u_int *value)
{
	socket_info_t *s = &socket[lsock];
	u_int pipr, reg;

#if (PCMCIA_SOCKETS_NO == 2)
	u_int _slot_ = s->slot;
#endif    

	pipr = ((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pipr;

	*value  = ((pipr & (M8XX_PCMCIA_CD1(_slot_) 
			    | M8XX_PCMCIA_CD2(_slot_))) == 0) ? SS_DETECT : 0;
	*value |= (pipr & M8XX_PCMCIA_WP(_slot_)) ? SS_WRPROT : 0;

	if (s->state.flags & SS_IOCARD)
		*value |= (pipr & M8XX_PCMCIA_BVD1(_slot_)) ? SS_STSCHG : 0;
	else {
		*value |= (pipr & M8XX_PCMCIA_RDY(_slot_)) ? SS_READY : 0;
		*value |= (pipr & M8XX_PCMCIA_BVD1(_slot_)) ? SS_BATDEAD : 0;
		*value |= (pipr & M8XX_PCMCIA_BVD2(_slot_)) ? SS_BATWARN : 0;
	}
	
	if (s->state.Vcc | s->state.Vpp)
		*value |= SS_POWERON;
	
	/*
	 * Voltage detection:
	 * This driver only supports 16-Bit pc-cards.
	 * Cardbus is not handled here.
	 * 
	 * To determine what voltage to use we must read the VS1 and VS2 pin.
	 * Depending on what socket type is present,
	 * different combinations mean different things.
	 *
	 * Card Key  Socket Key   VS1   VS2   Card         Vcc for CIS parse
	 *   
	 * 5V        5V, LV*      NC    NC    5V only       5V (if available)
	 *           
	 * 5V        5V, LV*      GND   NC    5 or 3.3V     as low as possible
	 *
	 * 5V        5V, LV*      GND   GND   5, 3.3, x.xV  as low as possible
	 *
	 * LV*       5V            -     -    shall not fit into socket
	 *
	 * LV*       LV*          GND   NC    3.3V only     3.3V
	 *
	 * LV*       LV*          NC    GND   x.xV          x.xV (if avail.)
	 *
	 * LV*       LV*          GND   GND   3.3 or x.xV   as low as possible
	 *
	 * *LV means Low Voltage
	 *
	 *
	 * That gives us the following table:
	 *
	 * Socket    VS1  VS2   Voltage
	 *
	 * 5V        NC   NC    5V
	 * 5V        NC   GND   none (should not be possible)
	 * 5V        GND  NC    >= 3.3V
	 * 5V        GND  GND   >= x.xV 
	 *
	 * LV        NC   NC    5V   (if available)
	 * LV        NC   GND   x.xV (if available)
	 * LV        GND  NC    3.3V 
	 * LV        GND  GND   >= x.xV 
	 * 
	 * So, how do I determine if I have a 5V or a LV
	 * socket on my board?  Look at the socket!
	 *
	 * 
	 * Socket with 5V key:
	 * ++--------------------------------------------+
	 * ||                                            |
	 * ||                                           ||
	 * ||                                           ||
	 * |                                             |
	 * +---------------------------------------------+
	 *
	 * Socket with LV key:
	 * ++--------------------------------------------+
	 * ||                                            |
	 * |                                            ||
	 * |                                            ||
	 * |                                             |
	 * +---------------------------------------------+
	 *
	 *
	 * With other words - LV only cards does not fit
	 * into the 5V socket!
	 */

	/* read out VS1 and VS2 */

	reg = (pipr & M8XX_PCMCIA_VS_MASK(_slot_)) 
		>> M8XX_PCMCIA_VS_SHIFT(_slot_);

	if(socket_get(_slot_) == PCMCIA_SOCKET_KEY_LV) {
		switch(reg) {
		case 1: *value |= SS_3VCARD; break; /* GND, NC - 3.3V only */
		case 2: *value |= SS_XVCARD; break; /* NC. GND - x.xV only */
		};
	}

	DEBUG(3,"GetStatus(%d) = %#2.2x\n", lsock, *value);
	return 0;
}
  
/* ------------------------------------------------------------------------- */

static int m8xx_inquire_socket(u_short lsock, socket_cap_t *cap)
{
	*cap = capabilities;

	return 0;
}

/* ------------------------------------------------------------------------- */

static int m8xx_get_socket(u_short lsock, socket_state_t *state)
{
	*state = socket[lsock].state; /* copy the whole structure */

	DEBUG(3,"GetSocket(%d) = flags %#3.3x, Vcc %d, Vpp %d, "
	      "io_irq %d, csc_mask %#2.2x\n", lsock, state->flags,
	      state->Vcc, state->Vpp, state->io_irq, state->csc_mask);
	return 0;
}

/* ------------------------------------------------------------------------- */

static int m8xx_set_socket(u_short lsock, socket_state_t *state)
{
	socket_info_t *s = &socket[lsock];
	event_table_t *e;
	u_int reg;
	u_long flags;

#if (PCMCIA_SOCKETS_NO == 2)
	u_int _slot_ = s->slot;
#endif    

	DEBUG(3, "SetSocket(%d, flags %#3.3x, Vcc %d, Vpp %d, "
	      "io_irq %d, csc_mask %#2.2x)\n", lsock, state->flags,
	      state->Vcc, state->Vpp, state->io_irq, state->csc_mask);

	/* First, set voltage - bail out if invalid */
    
	if(voltage_set(_slot_, state->Vcc, state->Vpp))
		return -EINVAL;


	/* Take care of reset... */

	if(state->flags & SS_RESET) 
		M8XX_PGCRX(_slot_) |=  M8XX_PGCRX_CXRESET; /* active high */
	else
		M8XX_PGCRX(_slot_) &= ~M8XX_PGCRX_CXRESET; 

	/* ... and output enable. */

	/* The CxOE signal is connected to a 74541 on the ADS.
	   I guess most other boards used the ADS as a reference.
	   I tried to control the CxOE signal with SS_OUTPUT_ENA,
	   but the reset signal seems connected via the 541. 
	   If the CxOE is left high are some signals tristated and
	   no pullups are present -> the cards act wierd.
	   So right now the buffers are enabled if the power is on. */

	if(state->Vcc || state->Vpp)
		M8XX_PGCRX(_slot_) &= ~M8XX_PGCRX_CXOE; /* active low */
	else
		M8XX_PGCRX(_slot_) |=  M8XX_PGCRX_CXOE;
	
	/* 
	 * We'd better turn off interrupts before 
	 * we mess with the events-table..
	 */

	save_flags(flags);
	cli();

	/*
	 * Play around with the interrupt mask to be able to
	 * give the events the generic pcmcia driver wants us to.
	 */

	e = &s->events[0]; 
	reg = 0;

	if(state->csc_mask & SS_DETECT) {
		e->eventbit = SS_DETECT;
		reg |= e->regbit = (M8XX_PCMCIA_CD2(_slot_) 
				    | M8XX_PCMCIA_CD1(_slot_));
		e++;
	}

	if(state->flags & SS_IOCARD) {

		/* 
		 * I/O card
		 */

		if(state->csc_mask & SS_STSCHG) {
			e->eventbit = SS_STSCHG;
			reg |= e->regbit = M8XX_PCMCIA_BVD1(_slot_);
			e++;
		}
		

		/*
		 * If io_irq is non-zero we should enable irq.
		 */

		if(state->io_irq) {
			M8XX_PGCRX(_slot_) |= 
				mk_int_int_mask(state->io_irq) << 24;

			/*
			 * Strange thing here:
			 * The manual does not tell us which interrupt
			 * the sources generate.
			 * Anyhow, I found out that RDY_L generates IREQLVL.
			 *
			 * We use level triggerd interrupts, and they don't
			 * have to be cleared in PSCR in the interrupt handler.
			 */

			reg |= M8XX_PCMCIA_RDY_L(_slot_);  
		}
		else
			M8XX_PGCRX(_slot_) &= 0x00ffffff;
		
#if 0
		if(state->flags & SS_SPKR_ENA)
			enablespeaker();
		else
			disablespeaker();
		
		if(state->flags & SS_DMA_MODE)
			enabledma();
		else
			disabledma();
#endif
		
	}
	else {
		
		/*
		 * Memory card
		 */
		
		if(state->csc_mask & SS_BATDEAD) {
			e->eventbit = SS_BATDEAD;
			reg |= e->regbit = M8XX_PCMCIA_BVD1(_slot_);
			e++;
		}
		
		if(state->csc_mask & SS_BATWARN) {
			e->eventbit = SS_BATWARN;
			reg |= e->regbit = M8XX_PCMCIA_BVD2(_slot_);
			e++;
		}
		
		/* What should I trigger on - low/high,raise,fall? */
		if(state->csc_mask & SS_READY) {
			e->eventbit = SS_READY;
			reg |= e->regbit = 0; //??
			e++;
		}
	}
	
	e->regbit = 0;  /* terminate list */
	
	/* 
	 * Clear the status changed .
	 * Port A and Port B share the same port.
	 * Writing ones will clear the bits.
	 */
	
	((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pscr = reg;
	
	/*
	 * Write the mask.
	 * Port A and Port B share the same port.
	 * Need for read-modify-write. 
	 * Ones will enable the interrupt.
	 */

	reg |= ((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_per 
		& M8XX_PCMCIA_MASK(_slot_);
	
	((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_per = reg;
	
	restore_flags(flags);

	/* copy the struct and modify the copy */
	
	s->state = *state;
	
	return 0;
}

/* ------------------------------------------------------------------------- */

static int m8xx_get_io_map(u_short lsock, struct pccard_io_map *io)
{
	if(io->map >= PCMCIA_IO_WIN_NO)
		return -EINVAL;

	*io = socket[lsock].io_win[io->map]; /* copy the struct */

	DEBUG(3,"GetIOMap(%d, %d) = %#2.2x, %d ns, "
	      "%#4.4x-%#4.4x\n", lsock, io->map, io->flags,
	      io->speed, io->start, io->stop);
	return 0;
}

/* ------------------------------------------------------------------------- */

static int m8xx_set_io_map(u_short lsock, struct pccard_io_map *io)
{
	socket_info_t *s = &socket[lsock];
	pcmcia_win_t *w;
	u_int reg, winnr;
	
#if (PCMCIA_SOCKETS_NO == 2)
	u_int _slot_ = s->slot;
#endif    

#if 1  
#define M8XX_SIZE (io->stop - io->start + 1)   
#define M8XX_BASE (PCMCIA_IO_WIN_BASE + io->start)
#else

/* only for testing */

#define M8XX_SIZE 0x400 // 0x10000      
#define M8XX_BASE PCMCIA_IO_WIN_BASE
#endif

	DEBUG(3, "SetIOMap(%d, %d, %#2.2x, %d ns, "
	      "%#4.4x-%#4.4x)\n", lsock, io->map, io->flags,
	      io->speed, io->start, io->stop);

	if ((io->map >= PCMCIA_IO_WIN_NO) || (io->start > 0xffff) 
	    || (io->stop > 0xffff) || (io->stop < io->start)) 
		return -EINVAL;
	
	if((reg = m8xx_get_graycode(M8XX_SIZE)) == -1)
		return -EINVAL;

	if(io->flags & MAP_ACTIVE) {

		winnr = (PCMCIA_MEM_WIN_NO * PCMCIA_SOCKETS_NO) 
			+ (lsock * PCMCIA_IO_WIN_NO) + io->map;
	
		/* setup registers */

		w = (void *) &((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pbr0;
		w += winnr;
	
		w->or = 0; /* turn off window first */
		w->br = M8XX_BASE;
	
		reg <<= 27;     
  		reg |= 0x00018 + (_slot_ << 2);

		reg |= m8xx_get_speed(io->speed, 1);

		if(io->flags & MAP_WRPROT) 
			reg |= 0x00000002;
		
		if(io->flags & (MAP_16BIT | MAP_AUTOSZ))
			reg |= 0x00000040;
	
		if(io->flags & MAP_ACTIVE) 
			reg |= 0x00000001;
	
		w->or = reg;

		DEBUG(3,"Socket %u: Mapped io window %u at %#8.8x, "
		      "OR = %#8.8x.\n", lsock, io->map, w->br, w->or);
#if 0
		if(0) {
			u_int k;

			printk("dumping map from 0x%02x\n", M8XX_BASE);
			
			for(k = M8XX_BASE; k < (M8XX_BASE+M8XX_SIZE); k++) {
				if(!(k & 0x0f))
					printk("0x%04x: ", k);
				
				printk("%02x ", *((char *) k));
				
				if((k & 0x0f) == 0x0f)
					printk("\n");
			}
			printk("\n");
		}
#endif
	}


	/* copy the struct and modify the copy */
	
	s->io_win[io->map] = *io; 
	s->io_win[io->map].flags &= (MAP_WRPROT 
				     | MAP_16BIT
				     | MAP_ACTIVE);
	return 0;
}

/* ------------------------------------------------------------------------- */

static int m8xx_get_mem_map(u_short lsock, struct pccard_mem_map *mem)
{
	if(mem->map >= PCMCIA_MEM_WIN_NO)
		return -EINVAL;
	
	*mem = socket[lsock].mem_win[mem->map]; /* copy the struct */
	
	DEBUG(3, "GetMemMap(%d, %d) = %#2.2x, %d ns, "
	      "%#5.5lx-%#5.5lx, %#5.5x\n", lsock, mem->map, mem->flags,
	      mem->speed, mem->sys_start, mem->sys_stop, mem->card_start);
	return 0;
}

/* ------------------------------------------------------------------------- */

static int m8xx_set_mem_map(u_short lsock, struct pccard_mem_map *mem)
{
	socket_info_t *s = &socket[lsock];
	pcmcia_win_t *w;
	struct pccard_mem_map *old;
	u_int reg, winnr;
	
#if (PCMCIA_SOCKETS_NO == 2)
	u_int _slot_ = s->slot;
#endif    

	DEBUG(3, "SetMemMap(%d, %d, %#2.2x, %d ns, "
	      "%#5.5lx-%#5.5lx, %#5.5x)\n", lsock, mem->map, mem->flags,
	      mem->speed, mem->sys_start, mem->sys_stop, mem->card_start);

	if ((mem->map >= PCMCIA_MEM_WIN_NO) || (mem->sys_start > mem->sys_stop)
	    || ((mem->sys_stop - mem->sys_start) >= PCMCIA_MEM_WIN_SIZE)
	    || (mem->card_start >= 0x04000000) 
	    || (mem->sys_start & 0xfff)                /* 4KByte resolution */
	    || (mem->card_start & 0xfff))                   
		return -EINVAL;
	
	if((reg = m8xx_get_graycode(PCMCIA_MEM_WIN_SIZE)) == -1) {
		printk( "Cannot set size to 0x%08x.\n", PCMCIA_MEM_WIN_SIZE);
		return -EINVAL;
	}

	winnr = (lsock * PCMCIA_MEM_WIN_NO) + mem->map;
	
	/* Setup the window in the pcmcia controller */
	
	w = (void *) &((immap_t *)IMAP_ADDR)->im_pcmcia.pcmc_pbr0;
	w += winnr;
	
	reg <<= 27;
	reg |= _slot_ << 2;
	
	reg |= m8xx_get_speed(mem->speed, 0);

	if(mem->flags & MAP_ATTRIB) 
		reg |= 0x00000010;
	
	if(mem->flags & MAP_WRPROT) 
		reg |= 0x00000002;
	
	if(mem->flags & MAP_16BIT) 
		reg |= 0x00000040;
	
	if(mem->flags & MAP_ACTIVE) 
		reg |= 0x00000001;
	
	w->or = reg;

	DEBUG(3, "Socket %u: Mapped memory window %u at %#8.8x, "
	      "OR = %#8.8x.\n", lsock, mem->map, w->br, w->or);

	if(mem->flags & MAP_ACTIVE) {

		mem->sys_stop -= mem->sys_start;

		/* get the new base address */
		
		mem->sys_start = PCMCIA_MEM_WIN_BASE + 
			(PCMCIA_MEM_WIN_SIZE * winnr)
			+ mem->card_start; 

		mem->sys_stop += mem->sys_start;
	}

DEBUG(3, "SetMemMap(%d, %d, %#2.2x, %d ns, "
	      "%#5.5lx-%#5.5lx, %#5.5x)\n", lsock, mem->map, mem->flags,
	      mem->speed, mem->sys_start, mem->sys_stop, mem->card_start);

	/* copy the struct and modify the copy */
	
	old = &s->mem_win[mem->map];
	
	*old = *mem;
	old->flags &= (MAP_ATTRIB
		       | MAP_WRPROT 
		       | MAP_16BIT
		       | MAP_ACTIVE);

	return 0;
}

/* ------------------------------------------------------------------------- */
    
static void *m8xx_services[] = {
	&m8xx_register_callback,
	&m8xx_inquire_socket,
	&m8xx_get_status,
	&m8xx_get_socket,
	&m8xx_set_socket,
	&m8xx_get_io_map,
	&m8xx_set_io_map,
	&m8xx_get_mem_map,
	&m8xx_set_mem_map,
};

#define NFUNC (sizeof(m8xx_services)/sizeof(void *))

static int m8xx_service(u_int lsock, u_int cmd, void *arg)
{
	DEBUG(3, "Service(%d, %d, 0x%p)\n", lsock, cmd, arg);

	if(cmd < NFUNC)
	    return ((int (*)(u_short, void *))m8xx_services[cmd])(lsock, arg);

	return -EINVAL;
}

/* ------------------------------------------------------------------------- */

module_init(m8xx_init);
module_exit(m8xx_exit);
