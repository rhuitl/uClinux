/*
 * can4linux.h - can4linux CAN driver module
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2001 port GmbH Halle/Saale
 *------------------------------------------------------------------
 * $Header: /cvs/sw/new-wave/user/can4linux/can4linux.h,v 1.2 2006-06-13 05:58:13 gerg Exp $
 *
 *--------------------------------------------------------------------------
 *
 *
 * modification history
 * --------------------
 * $Log: can4linux.h,v $
 * Revision 1.2  2006-06-13 05:58:13  gerg
 * #10381
 *
 * CAN tools update (to help support the M5329).
 *
 * Patch submitted by Matt Waddel <Matt.Waddel@freescale.com>
 *
 * Revision 1.1  2003/07/18 00:11:46  gerg
 * I followed as much rules as possible (I hope) and generated a patch for the
 * uClinux distribution. It contains an additional driver, the CAN driver, first
 * for an SJA1000 CAN controller:
 *   uClinux-dist/linux-2.4.x/drivers/char/can4linux
 * In the "user" section two entries
 *   uClinux-dist/user/can4linux     some very simple test examples
 *   uClinux-dist/user/horch         more sophisticated CAN analyzer example
 *
 * Patch submitted by Heinz-Juergen Oertel <oe@port.de>.
 *
 *
 *
 *
 *--------------------------------------------------------------------------
 */


/**
* \file can.h
* \author Heinz-Jürgen Oertel, port GmbH
* $Revision: 1.2 $
* $Date: 2006-06-13 05:58:13 $
*
* can4linux interface definitions
*
*
*
*/


#ifndef __CAN_H
#define __CAN_H


#ifndef __KERNEL__
#include <sys/time.h>
#endif
 /*---------- the can message structure */

#define CAN_MSG_LENGTH 8		/**< maximum length of a CAN frame */


#define MSG_RTR		(1<<0)		/**< RTR Message */
#define MSG_OVR		(1<<1)		/**< CAN controller Msg overflow error */
#define MSG_EXT		(1<<2)		/**< extended message format */
#define MSG_PASSIVE	(1<<4)		/**< controller in error passive */
#define MSG_BUSOFF      (1<<5)		/**< controller Bus Off  */
#define MSG_       	(1<<6)		/**<  */
#define MSG_BOVR	(1<<7)		/**< receive/transmit buffer overflow */
/**
* mask used for detecting CAN errors in the canmsg_t flags field
*/
#define MSG_ERR_MASK	(MSG_OVR + MSG_PASSIVE + MSG_BUSOFF + MSG_BOVR)

/**
* The CAN message structure.
* Used for all data transfers between the application and the driver
* using read() or write().
*/
typedef struct {
    /** flags, indicating or controlling special message properties */
    int             flags;
    int             cob;	 /**< CAN object number, used in Full CAN  */
    unsigned   long id;		 /**< CAN message ID, 4 bytes  */
    struct timeval  timestamp;	 /**< time stamp for received messages */
    short      int  length;	 /**< number of bytes in the CAN message */
    unsigned   char data[CAN_MSG_LENGTH]; /**< data, 0...8 bytes */
} canmsg_t;



/**
---------- IOCTL requests */

#define COMMAND 	 0	/**< IOCTL command request */
#define CONFIG 		 1	/**< IOCTL configuration request */
#define SEND 		 2	/**< IOCTL request */
#define RECEIVE 	 3	/**< IOCTL request */
#define CONFIGURERTR 	 4	/**< IOCTL request */
#define STATUS           5      /**< IOCTL status request */

/*---------- CAN ioctl parameter types */

/**
 IOCTL Command request parameter structure */
typedef struct Command_par {
    int cmd;			/**< special driver command */
    int error;	 		/**< return value */
    unsigned long retval;	/**< return value */
} Command_par_t ;


/**
 IOCTL Configuration request parameter structure */
typedef struct Config_par {
    int target;			/**< special configuration target */
    unsigned long val1;		/**< 1. parameter for the target */
    unsigned long val2;		/**< 2. parameter for the target */
    int error;	 		/**< return value for errno */
    unsigned long retval;	/**< return value */
} Config_par_t ;

/**
 IOCTL CAN controller status request parameter structure */
typedef struct CanSja1000Status_par { 
    unsigned int baud;			/**< actual bit rate */
    unsigned char status;		/**< CAN controller status register */
    unsigned int error_warning_limit;	/**< the error warning limit */
    unsigned int rx_errors;		/**< content of RX error counter */
    unsigned int tx_errors;		/**< content of TX error counter */
    unsigned int error_code;		/**< content of error code register */
    unsigned int rx_buffer_size;	/**< size of rx buffer  */
    unsigned int rx_buffer_used;	/**< number of messages */
    unsigned int tx_buffer_size;	/**< size of tx buffer  */
    unsigned int tx_buffer_used;	/**< number of messages */
    unsigned long retval;		/**< return value */
} CanSja1000Status_par_t;

/**
 IOCTL generic CAN controller status request parameter structure */
typedef struct CanStatusPar {
    unsigned int baud;                  /**< actual bit rate */
    unsigned long status;               /**< CAN controller status register */
    unsigned int error_warning_limit;   /**< the error warning limit */
    unsigned int rx_errors;             /**< content of RX error counter */
    unsigned int tx_errors;             /**< content of TX error counter */
    unsigned int error_code;            /**< content of error code register */
    unsigned int rx_buffer_size;        /**< size of rx buffer  */
    unsigned int rx_buffer_used;        /**< number of messages */
    unsigned int tx_buffer_size;        /**< size of tx buffer  */
    unsigned int tx_buffer_used;        /**< number of messages */
    unsigned long retval;               /**< return value */
    unsigned int type;                  /**< CAN controller / driver type */
} CanStatusPar_t;

/**
 IOCTL Send request parameter structure */
typedef struct Send_par {
    canmsg_t *Tx;		/**< CAN message struct  */
    int error;	 		/**< return value for errno */
    unsigned long retval;	/**< return value */
} Send_par_t ;

/**
 IOCTL Receive request parameter structure */
typedef struct Receive_par {
    canmsg_t *Rx;		/**< CAN message struct  */
    int error;	 		/**< return value for errno */
    unsigned long retval;	/**< return value */
} Receive_par_t ;

/**
IOCTL ConfigureRTR request parameter structure */
typedef struct ConfigureRTR_par {
    unsigned message;		/**< CAN message ID */
    canmsg_t *Tx;		/**< CAN message struct  */
    int error;	 		/**< return value for errno */
    unsigned long retval;	/**< return value */
} ConfigureRTR_par_t ;

/**
---------- IOCTL Command subcommands */

# define CMD_START	1
# define CMD_STOP 	2
# define CMD_RESET	3


/**
---------- IOCTL Configure targets */

# define CONF_ACC   	0	/* mask and code */
# define CONF_ACCM   	1	/* mask only */
# define CONF_ACCC   	2	/* code only */
# define CONF_TIMING	3	/* bit timing */
# define CONF_OMODE 	4	/* output control register */
# define CONF_FILTER	5
# define CONF_FENABLE	6
# define CONF_FDISABLE	7

#endif 	/* __CAN_H */
