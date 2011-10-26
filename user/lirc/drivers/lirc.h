/*      $Id: lirc.h,v 5.4 2000/04/24 19:41:42 columbus Exp $      */

#ifndef _LINUX_LIRC_H
#define _LINUX_LIRC_H

#include <limits.h>

#include <linux/ioctl.h>
#include <asm/types.h>

#define PULSE_BIT  0x01000000
#define PULSE_MASK 0x00FFFFFF

#if INT_MAX>=PULSE_BIT
typedef int lirc_t;
#else
#error "No appropriate type for lirc data available."
#endif


/*
 * lirc compatible hardware features
 */


#define LIRC_MODE2SEND(x) (x)
#define LIRC_SEND2MODE(x) (x)
#define LIRC_MODE2REC(x) ((x) << 16)
#define LIRC_REC2MODE(x) ((x) >> 16)

#define LIRC_MODE_RAW                  0x00000001
#define LIRC_MODE_PULSE                0x00000002
#define LIRC_MODE_MODE2                0x00000004
#define LIRC_MODE_CODE                 0x00000008
#define LIRC_MODE_LIRCCODE             0x00000010
#define LIRC_MODE_STRING               0x00000020


#define LIRC_CAN_SEND_RAW              LIRC_MODE2SEND(LIRC_MODE_RAW)
#define LIRC_CAN_SEND_PULSE            LIRC_MODE2SEND(LIRC_MODE_PULSE)
#define LIRC_CAN_SEND_MODE2            LIRC_MODE2SEND(LIRC_MODE_MODE2)
#define LIRC_CAN_SEND_CODE             LIRC_MODE2SEND(LIRC_MODE_CODE)
#define LIRC_CAN_SEND_LIRCCODE         LIRC_MODE2SEND(LIRC_MODE_LIRCCODE)
#define LIRC_CAN_SEND_STRING           LIRC_MODE2SEND(LIRC_MODE_STRING)

#define LIRC_CAN_SEND_MASK             0x0000003f

#define LIRC_CAN_SET_SEND_CARRIER      0x00000100
#define LIRC_CAN_SET_SEND_DUTY_CYCLE   0x00000200

#define LIRC_CAN_REC_RAW               LIRC_MODE2REC(LIRC_MODE_RAW)
#define LIRC_CAN_REC_PULSE             LIRC_MODE2REC(LIRC_MODE_PULSE)
#define LIRC_CAN_REC_MODE2             LIRC_MODE2REC(LIRC_MODE_MODE2)
#define LIRC_CAN_REC_CODE              LIRC_MODE2REC(LIRC_MODE_CODE)
#define LIRC_CAN_REC_LIRCCODE          LIRC_MODE2REC(LIRC_MODE_LIRCCODE)
#define LIRC_CAN_REC_STRING            LIRC_MODE2REC(LIRC_MODE_STRING)

#define LIRC_CAN_REC_MASK              LIRC_MODE2REC(LIRC_CAN_SEND_MASK)

#define LIRC_CAN_SET_REC_CARRIER       (LIRC_CAN_SET_SEND_CARRIER << 16)
#define LIRC_CAN_SET_REC_DUTY_CYCLE    (LIRC_CAN_SET_SEND_DUTY_CYCLE << 16)

#define LIRC_CAN_SET_REC_DUTY_CYCLE_RANGE 0x40000000
#define LIRC_CAN_SET_REC_CARRIER_RANGE    0x80000000


#define LIRC_CAN_SEND(x) ((x)&LIRC_CAN_SEND_MASK)
#define LIRC_CAN_REC(x) ((x)&LIRC_CAN_REC_MASK)

/*
 * IOCTL commands for lirc driver
 */

#define LIRC_GET_FEATURES              _IOR('i', 0x00000000, __u32)

#define LIRC_GET_SEND_MODE             _IOR('i', 0x00000001, __u32)
#define LIRC_GET_REC_MODE              _IOR('i', 0x00000002, __u32)
#define LIRC_GET_SEND_CARRIER          _IOR('i', 0x00000003, __u32)
#define LIRC_GET_REC_CARRIER           _IOR('i', 0x00000004, __u32)
#define LIRC_GET_SEND_DUTY_CYCLE       _IOR('i', 0x00000005, __u32)
#define LIRC_GET_REC_DUTY_CYCLE        _IOR('i', 0x00000006, __u32)

/* code length in bits, currently only for LIRC_MODE_LIRCCODE */
#define LIRC_GET_LENGTH                _IOR('i', 0x0000000f, __u32)

#define LIRC_SET_SEND_MODE             _IOW('i', 0x00000011, __u32)
#define LIRC_SET_REC_MODE              _IOW('i', 0x00000012, __u32)
/* Note: these can reset the according pulse_width */
#define LIRC_SET_SEND_CARRIER          _IOW('i', 0x00000013, __u32)
#define LIRC_SET_REC_CARRIER           _IOW('i', 0x00000014, __u32)
#define LIRC_SET_SEND_DUTY_CYCLE       _IOW('i', 0x00000015, __u32)
#define LIRC_SET_REC_DUTY_CYCLE        _IOW('i', 0x00000016, __u32)

#define LIRC_SET_REC_DUTY_CYCLE_RANGE  _IOW('i', 0x0000001e, __u32)
#define LIRC_SET_REC_CARRIER_RANGE     _IOW('i', 0x0000001f, __u32)

#endif
