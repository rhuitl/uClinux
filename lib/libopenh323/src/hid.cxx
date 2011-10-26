/*
 * hid.cxx
 *
 * Virteos HID Implementation for the OpenH323 Project.
 *
 * Virteos is a Trade Mark of ISVO (Asia) Pte Ltd.
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
 * The Initial Developer of the Original Code is ISVO (Asia) Pte Ltd.
 *
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: hid.cxx,v $
 * Revision 1.4  2005/08/23 08:10:12  shorne
 * Fix if not device available to return NULL
 *
 * Revision 1.3  2005/07/13 18:02:01  shorne
 * Added HIDdevices::AddAllHIDs
 *
 * Revision 1.2  2005/07/06 11:15:32  shorne
 * Added HIDdevices::PrintOn
 *
 * Revision 1.1  2005/07/03 14:38:13  shorne
 * Added Initial LID Plugin Support
 *
 *
*/

#include <ptlib.h>
#include <opalplugin.h>
#include "OpalUSBDevice.h"

#include "hid.h"


BOOL HIDDevices::HasAvailDevice()
{

	 for (PINDEX i = 0; i < GetSize(); i++) {
		if ((*this)[i].IsOpen())
			return TRUE;
	 }

     return FALSE;
}
	  
OpalLineInterfaceDevice * HIDDevices::AvailDevice()
{

	if (GetSize() == 0)   /// No HID Devices
		return NULL;

	for (PINDEX i = 0; i < GetSize(); i++) {  /// Opened Device
		if ((*this)[i].IsOpen())
			return &(*this)[i];
	 }
	 
	 return NULL;   /// No available devices
}

static BOOL MatchWildcard(const PCaselessString & str, const PStringArray & wildcard)
{
  PINDEX last = 0;
  for (PINDEX i = 0; i < wildcard.GetSize(); i++) {
    if (wildcard[i].IsEmpty())
      last = str.GetLength();
    else {
      PINDEX next = str.Find(wildcard[i], last);
      if (next == P_MAX_INDEX)
        return FALSE;
      last = next + wildcard[i].GetLength();
    }
  }

  return TRUE;
}
  
BOOL HIDDevices::AddAllHIDs(const PString & name)
{
  HIDFactory::KeyList_T keyList = HIDFactory::GetKeyList();
  HIDFactory::KeyList_T::const_iterator r;
  PStringArray wildcard = name.Tokenise('*', FALSE);

   for (r = keyList.begin(); r != keyList.end(); ++r) {
    PCaselessString capName = *r;
     if (MatchWildcard(capName, wildcard)) {
       OpalLineInterfaceDevice * dev = HIDFactory::CreateInstance(*r);
       if (dev->Open(PString()))
		  Append(dev);
     }
   }
	return TRUE;
}

void HIDDevices::PrintOn(ostream & strm) const
{
  int indent = strm.precision()-1;
  strm << setw(indent) << " " << "Table:\n";
  for (PINDEX i = 0; i < GetSize(); i++)
    strm << setw(indent+2) << " " << (*this)[i] << " <" << i+1 << ">" << '\n';
}

////////////////////////////////////////////////////////////////

HIDPluginDeviceManager::HIDPluginDeviceManager(PPluginManager * _pluginMgr)
 : PPluginModuleManager(PLUGIN_HID_GET_DEVICE_FN_STR, _pluginMgr)
{
 /*cout << */ PTRACE(3, "H323HID\tPlugin loading HID" /*<< endl;*/ ); 

	  // cause the plugin manager to load all dynamic plugins
  pluginMgr->AddNotifier(PCREATE_NOTIFIER(OnLoadModule), TRUE);
}
    
HIDPluginDeviceManager::~HIDPluginDeviceManager()
{

}

void HIDPluginDeviceManager::OnLoadPlugin(PDynaLink & dll, INT code)
{
  PluginHID_GetHIDFunction getHIDs;
  if (!dll.GetFunction(PString(signatureFunctionName), (PDynaLink::Function &)getHIDs)) {
 /* cout << */ PTRACE(3, "H323HID\tPlugin HID DLL " << dll.GetName() << " is not a plugin HID" /*<< endl;*/ );	  
    return;
  }

  unsigned int count;
  PluginHID_Definition * hids = (*getHIDs)(&count, PLUGIN_HID_VERSION);
  if (hids == NULL || count == 0) {
 /* cout <<*/ PTRACE(3, "H323PLUGIN\tPlugin HID DLL " << dll.GetName() << " contains no HID definitions" /*<< endl;*/ );
    return;
  } 

 /* cout <<*/ PTRACE(3, "H323PLUGIN\tLoading plugin HID " << dll.GetName() /*<< endl;*/ );

  switch (code) {

    // plugin loaded
    case 0:
      RegisterHID(count, hids);
      break;

    // plugin unloaded
    case 1:
      UnregisterHID(count, hids);
      break;

    default:
      break;
  }
}

void HIDPluginDeviceManager::OnShutdown()
{
  // unregister the plugin HIDs
    HIDFactory::UnregisterAll();
}

void HIDPluginDeviceManager::Bootstrap()
{

}

BOOL HIDPluginDeviceManager::RegisterHID(unsigned int count, void * _HIDList)
{
  // make sure all non-timestamped codecs have the same concept of "now"
  static time_t HIDNow = ::time(NULL);

  PluginHID_Definition * HIDList = (PluginHID_Definition *)_HIDList;

  unsigned i;
  for (i = 0; i < count; i++) {
		CreateHIDDevice(&HIDList[i]);
  }

  return TRUE;
}

BOOL HIDPluginDeviceManager::UnregisterHID(unsigned int /*count*/, void * /*_HIDList*/)
{

	return FALSE;
}

static PString CreateHIDName(PluginHID_Definition * hid, unsigned int HIDtype)
{
  PString str;

  switch (HIDtype) {
  case PluginHID_TypeUSBAudio:
    str = hid->descr + PString(" (USB)");
	break;

   default:
	str = hid->descr & PString(" (PCI)");
  }

  return str;
}

void HIDPluginDeviceManager::CreateHIDDevice(PluginHID_Definition * HIDDevice)
{
  // make sure all non-timestamped codecs have the same concept of "now"
  static time_t mediaNow = time(NULL);

  // deal with codec having no info, or timestamp in future
  time_t timeStamp = HIDDevice->info == NULL ? mediaNow : HIDDevice->info->timestamp;
  if (timeStamp > mediaNow)
    timeStamp = mediaNow;

// Device Name
  PString devName; 
  OpalLineInterfaceDevice * dev = NULL;


// Type of HID Plugin
  switch (HIDDevice->flags & PluginHID_TypeMask) {
	case PluginHID_TypeUSBAudio:
		devName = CreateHIDName(HIDDevice, PluginHID_TypeUSBAudio);
		dev = new OpalUSBDevice(HIDDevice);
		break;
	default:
		devName = CreateHIDName(HIDDevice, PluginHID_TypeMask);
		break;
  }	   

  if (dev != NULL)
	   HIDFactory::Register(devName, dev);
}