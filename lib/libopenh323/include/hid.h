/*
 * hid.h
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
 * $Log: hid.h,v $
 * Revision 1.3  2005/07/13 18:01:01  shorne
 * Added HIDdevices::AddAllHIDs
 *
 * Revision 1.2  2005/07/06 11:15:25  shorne
 * Added HIDdevices::PrintOn
 *
 * Revision 1.1  2005/07/03 14:38:42  shorne
 * *** empty log message ***
 *
 *
*/

#include <ptlib.h>
#include <lid.h>

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef _MSC_VER
#pragma warning(disable:4100)
#endif


PDECLARE_LIST(HIDDevices, OpalLineInterfaceDevice)
#ifdef DOC_PLUS_PLUS
{
#endif
  public:
	BOOL HasAvailDevice();
	OpalLineInterfaceDevice * AvailDevice();
	BOOL AddAllHIDs(const PString & name);

        void PrintOn(ostream & strm) const;
};

class HIDPluginDeviceManager : public PPluginModuleManager
{
  PCLASSINFO(HIDPluginDeviceManager, PPluginModuleManager);
  public:
    HIDPluginDeviceManager(PPluginManager * pluginMgr = NULL);
    ~HIDPluginDeviceManager();

    void OnLoadPlugin(PDynaLink & dll, INT code);

    virtual void OnShutdown();

    static void Bootstrap();

	virtual BOOL RegisterHID(unsigned int count, void * _HIDList);
	virtual BOOL UnregisterHID(unsigned int count, void * _HIDList);

	void CreateHIDDevice(PluginHID_Definition * HIDDevice);


};

static PFactory<PPluginModuleManager>::Worker<HIDPluginDeviceManager> h323PluginCodecManagerFactory("HIDPluginDeviceManager", true);

///////////////////////////////////////////////////////////////////////////////

typedef PFactory<OpalLineInterfaceDevice> HIDFactory;

#define HID_REGISTER_DEVICE(cls, HIDName)   static HIDFactory::Worker<cls> cls##Factory(HIDName, true); \

#define HID_DEFINE_DEVICE(cls, HIDName, fmtName) \
class cls : public OpalLineInterfaceDevice { \
  public: \
    cls() : OpalLineInterfaceDevice() { } \
    PString GetName() const \
    { return fmtName; } \
}; \
 HID_REGISTER_DEVICE(cls, capName) \

/////////////////////////////////////////////////////////////////////////////