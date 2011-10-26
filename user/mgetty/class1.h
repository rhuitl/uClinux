#define FRAMESIZE	300

typedef unsigned char uch;

extern int fax1_dis;		/* "X"-Bit (received DIS) */

RETSIGTYPE fax1_sig_alarm(SIG_HDLR_ARGS);
void fax1_dump_frame _PROTO(( uch * frame, int len ));

int fax1_send_page _PROTO(( char * g3_file, int * bytes_sent, TIO * tio,
			    Post_page_messages ppm, int fd ));

void fax1_copy_id _PROTO(( uch * frame ));

struct fax1_btable { int speed;			/* bit rate */
                     int flag;			/* flag (for capabilities) */
		     int c_long, c_short;	/* carrier numbers */
		     int dcs_bits;		/* bits to be set in DCS */
		    };
struct fax1_btable * dcs_btp;			/* current modulation */

/* --- Definitions from ITU T.30, 07/96 --- */

/* control field - bit set on final frame, T.30 5.3.5 */
#define T30_FINAL	0x10

/* frame types (FCF), T.30 5.3.6, bits reversed! */
#define T30_DIS	0x80		/* Digital Information Signal */
#define T30_CSI	0x40		/* Called Subscriber Information */
#define T30_NSF	0x20		/* Non-Standard Facilities */

#define T30_DTC	0x81		/* Digital Transmit Command */
#define T30_CIG	0x41		/* Calling Subscriber Information */
#define T30_NSC	0x21		/* Non-Standard facilities Command */
#define T30_PWD 0xc1		/* Password (for polling) */
#define T30_SEP 0xa1		/* Selective Polling (subaddress) */

#define	T30_DCS	0x82		/* Digital Command Signal */
#define T30_TSI	0x42		/* Transmit Subscriber Information */
#define T30_NSS	0x22		/* Non-Standard facilities Setup */
#define T30_SUB 0xc2		/* Subaddress */
#define T30_PWDT 0xa2		/* Password for Transmission */

#define T30_CFR	0x84		/* Confirmation To Receive */
#define T30_FTT 0x44		/* Failure To Train */

#define T30_EOM	0x8e		/* End Of Message (end of page -> phase B) */
#define T30_MPS 0x4e		/* MultiPage Signal (end of page -> phase C) */
#define T30_EOP 0x2e		/* End Of Procedures (over and out) */
#define T30_PRI_EOM	0x9e	/* EOM + PRI */
#define T30_PRI_MPS	0x5e	/* MPS + PRI */
#define T30_PRI_EOP	0x3e	/* EOP + PRI */
#define T30_PRI		0x10	/* bit 4 in FCF -> Procedure Interrupt */

#define T30_MCF	0x8c		/* Message Confirmation (page good) */
#define T30_RTP	0xcc		/* Retrain Positive */
#define T30_RTN	0x4c		/* Retrain Negative */
#define T30_PIP	0xac		/* Procedure Interrupt Positive */
#define T30_PIN	0x2c		/* Procedure Interrupt Negative */

#define T30_DCN	0xfc		/* Disconnect Now (phase E) */
#define T30_CRP	0x1c		/* Command Repeat (optional) */
