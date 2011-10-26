#ident "$Id: fax_lib.h,v 4.10 2003/06/12 20:41:34 gert Exp $ Copyright (c) Gert Doering"


/* fax_lib.h
 * 
 * declare protopes for all the fax functions in faxrec.c and faxlib.c
 * declare global variables set by functions in faxlib.c
 * declare all the constants required for Class 2 faxing
 */

/* data types + variables */

typedef enum { Mt_unknown, Mt_data, 
		Mt_class1,	/* TIA/EIA 578 standard */
		Mt_class1_0,	/* ITU T.31 standard */
		Mt_class2, 	/* SP-2388 / EIA 592 drafts */
		Mt_class2_0,	/* TIA/EIA 592 standard */
		Mt_class2_1	/* ITU T.32 standard */
		} Modem_type;
extern Modem_type modem_type;

typedef enum { pp_mps, pp_eom, pp_eop,
	       pp_pri_mps, pp_pri_eom, pp_pri_eop } Post_page_messages;

extern unsigned char fax_send_swaptable[];

/* function prototypes */

int fax_send _PROTO(( char * s, int fd ));	/* write to fd, with logging */
                                         /* expect string, handle fax msgs */
int fax_wait_for _PROTO(( char * s, int fd ));
int fax_command _PROTO(( char * send, char * expect, int fd ));

int fax_get_pages _PROTO(( int fd, int * pagenum, char * directory,
			   int uid, int gid, int mode ));
int fax_get_page_data _PROTO(( int modem_fd, int pagenum, char * directory,
			       int uid, int gid, int file_mode ));

int fax_set_l_id _PROTO(( int fd, char * fax_id ));
int fax_set_fdcc _PROTO(( int fd, int fine, int maxsp, int minsp ));
int fax_set_bor  _PROTO(( int fd, int bit_order ));
int fax_set_flowcontrol _PROTO(( int fd, int hw_flow ));
int mdm_identify _PROTO(( int fd ));

#ifdef __TIO_H__
int fax_send_page _PROTO(( char * g3_file, int * bytes_sent, TIO * tio,
			   Post_page_messages ppm, int fd ));
int fax_send_ppm  _PROTO(( int fd, TIO *tio, Post_page_messages ppm ));
#endif

Modem_type fax_get_modem_type _PROTO(( int fd, char * mclass ));

typedef	struct	{ short vr, br, wd, ln, df, ec, bf, st; } fax_param_t;

extern	char	fax_remote_id[];		/* remote FAX id +FTSI */
extern	char	fax_param[];			/* transm. parameters +FDCS */
extern	char	fax_hangup;
extern	int	fax_hangup_code;
extern	int	fax_page_tx_status;
extern	fax_param_t	fax_par_d;
extern	boolean	fax_to_poll;			/* there's something */
						/* to poll */
extern	boolean	fax_poll_req;			/* caller wants to poll */

extern	boolean	fhs_details;			/* +FHS:x,lc info avail.*/
extern	int	fhs_lc, fhs_blc, fhs_cblc, fhs_lbc;	/* details */

extern	int	modem_quirks;			/* modem specials */


/* fax_hangup_code gives the reason for failure, normally it's a positive
 * number returned by the faxmodem in the "+FHNG:iii" response. If the
 * modem returned BUSY or NO_CARRIER or ERROR, we use negative numbers to
 * signal what has happened. "-5" means something toally unexpeced.
 */

#define	FHUP_BUSY	-2
#define FHUP_NODIAL	-3
#define FHUP_ERROR	-4
#define FHUP_UNKNOWN	-5
#define FHUP_TIMEOUT    -6

#define ETX	003
#define DLE	020
#define SUB	032
#define DC2	022
#define XON	021
#define XOFF	023

#ifndef ERROR
#define	ERROR	-1
#define NOERROR	0
#endif

/* modem_quirks specifies some details in this modem's implementation
 * that are just *different* from the usual...
 */

#define MQ_NEED2	0x01	/* must be in +FCLASS=2 for +FAA=1 to work */
#define MQ_FBOR_OK	0x02	/* +FBOR implemented correctly (Multitech) */
#define MQ_NO_LQC	0x04	/* +FPS:x,lc,blc can't be trusted */
#define MQ_NO_XON	0x08	/* do not wait for XON char when sending */
#define MQ_USR_FMINSP	0x20	/* USR: +FCC=1,<max> sets MIN speed instead */
#define MQ_SHOW_NSF	0x40	/* set AT+FNR=1,1,1,1 (with NSFs) */
#define MQ_FPS_NOT_HEX	0x80	/* +FPS:<status>,<lc> reported as decimal */

/* note: 0x100 and 0x200 currently used for teergrubing - faxrecp.c */
