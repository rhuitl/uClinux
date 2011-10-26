/*
 * device_mode_names.c
 *
 * delivers a printable name for the voice_devices chosen by 
 * the identifier device_number
 *
 * $Id: device_mode_names.c,v 1.1 2001/02/24 10:59:37 marcs Exp $
 *
 */

#include "../include/voice.h"

char *voice_device_mode_name(int device_number)
     {
       char* device_name[NUMBER_OF_MODEM_DEVICE_MODES+1] =
       {"undefined", 
	"No Device", 
	"Dialup Line", 
	"Ext. Microphone", 
	"Int. Microphone", 
	"Ext. Speaker", 
	"Int. Speaker", 
	"Local Handset", 
	"Dialup Line and Ext. Speaker", 
	"Dialup Line and Int. Speaker", 
	"Dialup Line and Local Handset", 
	"Dialup Line, Ext. Mic. and Ext. Speaker", 
	"Dialup Line, Int. Mic. and Int. Speaker"};

     if (device_number > NUMBER_OF_MODEM_DEVICE_MODES)
       {
	 return(device_name[0]);
       }
     else 
       {
	 return(device_name[device_number]);
       };
     }







