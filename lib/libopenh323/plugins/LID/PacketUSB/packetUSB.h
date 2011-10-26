/* packetUSB.h
 *
 * Packetizer USB Plugin for OpenH323/OPAL
 *
 * Copyright (c) 2005 ISVO (Asia) Pte Ltd. All Rights Reserved.
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is derived from and used in conjunction with the 
 * OpenH323/OPAL Project (www.openh323.org/)
 *
 * The Initial Developer of the Original Code is ISVO (Asia) Pte Ltd.
 *
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: packetUSB.h,v $
 * Revision 1.2  2005/08/23 07:32:59  shorne
 * Greatly simplified plugin / added volume support
 *
 *
*/

#include <opalplugin.h>
#include <windows.h>

#if _MSC_VER > 1000
#pragma once
#endif 

extern "C" {
   PLUGIN_HID_IMPLEMENT("PacketUSB")
}


////////////////////////////////////////////////////////////////////////////
// Information

static struct PluginHID_information licenseInfo = {
  1073619586,                              // timestamp = Fri 09 Jan 2004 03:39:46 AM UTC = 

  "Simon Horne	ISVO(Asia) Pte Ltd",                           // source code author
  "1.0",                                                       // source code version
  "shorne@isvo.net",		                                   // source code email
  "http://www.isvo.net",					   // source code URL
  "Copyright (C) 2005 by ISVO (Asia), All Rights Reserved",	   // source code copyright
  "MPL 1.0",                                                   // source code license
  PluginCodec_License_MPL,                                     // source code license

  "Packetizer USB",                                               // HID description
  "Packetizer",							// codec author
  NULL,                                                        // Model
  NULL,                                                        // Model email
  "http://www.packetizer.com",                                // codec URL
};

////////////////////////////////////////////////////////////////////////////
// Codec Information Template

#define DECLARE_PARAM(prefix) \
{ \
  /* encoder */ \
  PLUGIN_HID_VERSION,	  	      /* codec API version */ \
  &licenseInfo,                       /* license information */ \
  PluginHID_TypeUSBAudio |            /* USB Audio Device */ \
  PluginHID_Tone |          	      /* No Tone Generator */ \
  PluginHID_DeviceCell |              /* Behave like a cell phone */ \
  PluginHID_DeviceSound,	      /* Is Regular Sound Device */ \
  prefix##_Desc,                      /* text decription */ \
  prefix##_Sound,                     /* sound device name  */ \
  create_HID,                         /* create HID function */ \
  destroy_HID,                        /* destroy HID */ \
  HID_Function,                       /* encode/decode */ \
  display_HID                         /* LCD Display */ \
} \

static const char		PacketUSB_Desc[] = { "PacketUSB" };	// text decription 
static const char		PacketUSB_Sound[] = { "USB Audio" }; // Sound Device Name
