/*
 * LIRC base driver
 * 
 * (L) by Artur Lipowski <alipowski@kki.net.pl>
 *        This code is licensed under GNU GPL
 *
 * $Id: lirc_dev.h,v 1.3 2000/12/03 18:02:55 columbus Exp $
 *
 */

#ifndef _LINUX_LIRC_DEV_H
#define _LINUX_LIRC_DEV_H

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 3, 0)
/* comes with bttv */
#include "../drivers/char/kcompat24.h"
#endif

#define MAX_IRCTL_DEVICES 2
#define BUFLEN            16

struct lirc_plugin
{
     char name[40];
     int minor;
     int code_length;
     int sample_rate;
     void* data;
     int (*get_key) (void* data, unsigned char* key, int key_no);
     wait_queue_head_t* (*get_queue) (void* data);
     void (*set_use_inc) (void* data);
     void (*set_use_dec) (void* data);
};
/* name:
 * this string will be used for logs
 *
 * minor:
 * indicates minor device (/dev/lircd) number for registered plugin
 * if caller fills it with negative value, then the first free minor 
 * number will be used (if available)
 *
 * code_length:
 * length ofthe  remote control key code expressed in bits
 * if code_length > 8 then many bytes are returned through the device read
 * in such situation get_key should return key code values starting
 * from most significant byte (device read will preseve this order)
 * in addition if code_length > 8 then get_key will be called 
 * several (ceil(code_length/8)) times in one pool pass (or after task queue 
 * awake) key_no parameter denotes number of the requested byte (0 means first 
 * byte)
 *
 * sample_rate:
 * sample_rate equal to 0 means that no pooling will be performed and get_key
 * will be triggered by external events (through task queue returned by 
 * get_queue)
 *
 * data:
 * it may point to any plugin data and this pointer will be passed to all 
 * callback functions
 *
 * get_key:
 * get_key will be called after specified period of the time or triggered by the 
 * external event, this behavior depends on value of the sample_rate
 * this function will be called in user context
 *
 * get_queue:
 * this callback should return a pointer to the task queue which will be used 
 * for external event waiting
 *
 * set_use_inc:
 * set_use_inc will be called after device is opened
 *
 * set_use_dec:
 * set_use_dec will be called after device is closed
 */


/* following functions can be called ONLY from user context
 *
 * returns negative value on error or minor number 
 * of the registered device if success
 * contens of the structure pointed by p is copied
 */
extern int lirc_register_plugin(struct lirc_plugin *p);

/* returns negative value on error or 0 if success
*/
extern int lirc_unregister_plugin(int minor);


#endif
