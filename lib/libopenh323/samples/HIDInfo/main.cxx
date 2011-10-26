/*
 * main.cxx
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
 * $Log: main.cxx,v $
 * Revision 1.4  2005/09/04 05:08:07  shorne
 * added support for POTS and cordless USB HID devices
 *
 * Revision 1.3  2005/08/23 07:30:18  shorne
 * Fixed small typo
 *
 * Revision 1.2  2005/07/13 16:36:20  shorne
 * Corrected ringing cadence
 *
 * Revision 1.1  2005/07/03 13:57:53  shorne
 * Initial commit
 *
 *
*/


#include <ptlib.h>
#include <h323.h>
#include <hid.h>

#ifdef __GNUC__
#define H323_STATIC_LIB
#endif


class HIDInfo : public PProcess
{
  PCLASSINFO(HIDInfo, PProcess)

  public:
    HIDInfo();

    void Main();

	PINLINE OpalLineInterfaceDevice * lidDevice() 
			{ return HIDdevice.AvailDevice(); }


  protected:
	HIDDevices HIDdevice;

	PThread  *  MonitorThread;							/// Monitor Thread. 
	PSyncPoint monitorTickle;							/// Poll wait
    PDECLARE_NOTIFIER(PThread, HIDInfo, Monitor);		/// Declaration of the Thread
	BOOL exitFlag;										/// Exit Thread Monitor Flag

};

#define new PNEW

PCREATE_PROCESS(HIDInfo)

///////////////////////////////////////////////////////////////

HIDInfo::HIDInfo()
  : PProcess("Virteos", "HIDInfo")
{								
}

PString DisplayLicenseType(int type)
{
  PString str;
  switch (type) {
    case PluginCodec_Licence_None:
      str = "No license";
      break;
    case PluginCodec_License_GPL:
      str = "GPL";
      break;
    case PluginCodec_License_MPL:
      str = "MPL";
      break;
    case PluginCodec_License_Freeware:
      str = "Freeware";
      break;
    case PluginCodec_License_ResearchAndDevelopmentUseOnly:
      str = "Research and development use only";
      break;
    case PluginCodec_License_BSD:
      str = "BSD";
      break;
    default:
      if (type <= PluginCodec_License_NoRoyalties)
        str = "No royalty license";
      else
        str = "Requires royalties";
      break;
  }
  return str;
}

PString DisplayableString(const char * str)
{
  if (str == NULL)
    return PString("(none)");
  return PString(str);
}

PString DisplayLicenseInfo(PluginHID_information * info)
{
  PStringStream str;
  if (info == NULL) 
    str << "    None" << endl;
  else {
    str << "  License" << endl
        << "    Timestamp: " << PTime().AsString(PTime::RFC1123) << endl
        << "    Source" << endl
        << "      Author:       " << DisplayableString(info->sourceAuthor) << endl
        << "      Version:      " << DisplayableString(info->sourceVersion) << endl
        << "      Email:        " << DisplayableString(info->sourceEmail) << endl
        << "      URL:          " << DisplayableString(info->sourceURL) << endl
        << "      Copyright:    " << DisplayableString(info->sourceCopyright) << endl
        << "      License:      " << DisplayableString(info->sourceLicense) << endl
        << "      License Type: " << DisplayLicenseType(info->sourceLicenseCode) << endl
        << "    Device" << endl
        << "      Description:  " << DisplayableString(info->HIDDescription) << endl
        << "      Manufacture:  " << DisplayableString(info->HIDManufacturer) << endl
        << "      Version:      " << DisplayableString(info->HIDModel) << endl
        << "      Email:        " << DisplayableString(info->HIDEmail) << endl
        << "      URL:          " << DisplayableString(info->HIDURL) << endl;
  }
  return str;
}

void DisplayHIDDefn(PluginHID_Definition & defn)
{
  cout << "  Version:             " << defn.version << endl
       << DisplayLicenseInfo(defn.info)
       << "  Flags:               ";
  switch (defn.flags & PluginHID_TypeMask) {
    case PluginHID_TypeUSBAudio:
      cout << "USB Audio, ";
      break;
    default:
      cout << "unknown type " << (defn.flags & PluginHID_TypeMask) << ", ";
      break;
  }

  switch (defn.flags & PluginHID_ToneMask) {
    case PluginHID_Tone:
      cout << "No Inbuilt Tone Generator, ";
      break;
    default:
      cout << "Inbuilt Tone Generator, ";
      break;
  }

  switch (defn.flags & PluginHID_GatewayMask) {
    case PluginHID_PSTN:
      cout << "PSTN capability, ";
      break;
    default:
      cout << "No PSTN Capability, ";
      break;
  }

  switch (defn.flags & PluginHID_DeviceTypeMask) {
    case PluginHID_DeviceCell:
      cout << "Cell Phone, ";
      break;
    default:
      cout << "POTS Phone, ";
      break;
  }

  switch (defn.flags & PluginHID_DeviceSoundMask) {
    case PluginHID_DeviceSound:
      cout << "Use Regular Sound/Record ";
      break;
    default:
      cout << "Use Internal Sound/Record ";
      break;
  }
}


void HIDInfo::Main()
{
  cout << GetName()
       << " Version " << GetVersion(TRUE)
       << " by " << GetManufacturer()
       << " on " << GetOSClass() << ' ' << GetOSName()
       << " (" << GetOSVersion() << '-' << GetOSHardware() << ")\n\n";

  HIDPluginDeviceManager & HIDMgr = *(HIDPluginDeviceManager *)PFactory<PPluginModuleManager>::CreateInstance("HIDPluginDeviceManager");

  PPluginModuleManager::PluginListType pluginList = HIDMgr.GetPluginList();
  HIDFactory::KeyList_T keyList = HIDFactory::GetKeyList();
  HIDFactory::KeyList_T::const_iterator r;

    for (int i = 0; i < pluginList.GetSize(); i++) {
        PDynaLink & dll = pluginList.GetDataAt(i);
        PluginHID_GetHIDFunction getHID;
        if (!dll.GetFunction(PLUGIN_HID_GET_DEVICE_FN_STR, (PDynaLink::Function &)getHID)) {
          cout << "error: " << pluginList.GetKeyAt(i) << " is missing the function " << PLUGIN_HID_GET_DEVICE_FN_STR << endl;
          return;
        }
       unsigned int count;
        PluginHID_Definition * hid = (*getHID)(&count, PLUGIN_HID_VERSION);
        if (hid == NULL || count == 0) {
          cout << "error: " << pluginList.GetKeyAt(i) << " does not define any HID for this version of the plugin API" << endl;
          return;
        } 
        cout << pluginList.GetKeyAt(i) << " contains " << count << " HIDs:" << endl;
        for (unsigned j = 0; j < count; j++) {
          cout << "---------------------------------------" << endl
               << "Coder " << i+1 << endl;

		    DisplayHIDDefn(hid[j]);
		  cout << endl;
        }

	}

    cout << "Registered HIDs:" << endl
         << setfill(',') << PStringArray(keyList) << setfill(' ')
         << endl;

   
   for (r = keyList.begin(); r != keyList.end(); ++r) {
     OpalLineInterfaceDevice * dev = HIDFactory::CreateInstance(*r);
	
    if (dev->Open(PString()))
		cout << dev->GetName() << " Device Monitor Started" << endl;

		HIDdevice.Append(dev);
   }

	MonitorThread = PThread::Create(PCREATE_NOTIFIER(Monitor), 0,
                            PThread::NoAutoDeleteThread,
                            PThread::NormalPriority,
                           "HIDMonitor:%x");
    
  cout << endl << "HID MENU:" << endl;
  cout << "	   A - Play ringing tone" << endl;
  cout << "	   B - Play busy tone" << endl;
  cout << "	   D = Play Dial tone" << endl;
  cout << "	   R - Ring Device" << endl;
  cout << "	   S - Stop Tones/Ringing" << endl;

  cout << "	   X - Exit Program." << endl;

  // Simplest possible user interface
  for (;;) {
    cout << "HID> " << flush;
    PCaselessString cmd;
    cin >> cmd;
    if (cmd == "X")
      break;

	if (cmd == "R") {
		if (lidDevice() != NULL) {
	          lidDevice()->RingLine(0, 0x33);
		  cout << "Ringing " << lidDevice()->GetName() << endl << flush;
		}

	} else if (cmd == "S") {
		if (lidDevice() != NULL) {
	       lidDevice()->StopTone(0);
		   cout << "Stop Tone " << lidDevice()->GetName() << endl << flush;
		}

	} else if (cmd == "D") {
		if (lidDevice() != NULL) {
	       lidDevice()->PlayTone(0,OpalLineInterfaceDevice::DialTone);
		   cout << "Dial Tone " << lidDevice()->GetName() << endl << flush;
		} 

	} else if (cmd == "B") {
		if (lidDevice() != NULL) {
	       lidDevice()->PlayTone(0,OpalLineInterfaceDevice::BusyTone);
		   cout << "Busy Tone " << lidDevice()->GetName() << endl << flush;
		} 

	} else if (cmd == "A") {
		if (lidDevice() != NULL) {
	      lidDevice()->PlayTone(0,OpalLineInterfaceDevice::RingTone);
		   cout << "Call Tone " << lidDevice()->GetName() << endl << flush;
		}
	} else {
		if (lidDevice() != NULL) 
	       lidDevice()->PlayDTMF(0,cmd);
		
	}
  }

	exitFlag = TRUE;
	monitorTickle.Signal();
	MonitorThread->WaitForTermination();

}

void HIDInfo::Monitor(PThread &, INT)
{

BOOL OldOffHook = FALSE;
BOOL OffHook = FALSE;
BOOL OnCallState = FALSE;
PString DigitBin = PString();

	for (;;) {
		if (exitFlag)
			break;

		if (lidDevice() != NULL) {
		if (lidDevice()->GetDeviceType() != OpalLineInterfaceDevice::CellEmulate) { 
			OffHook = lidDevice()->IsLineOffHook(0);
			if (OffHook != OldOffHook) {
				if (OffHook) {
					lidDevice()->PlayTone(0,OpalLineInterfaceDevice::DialTone);	
				} else {
					lidDevice()->StopTone(0);
					OnCallState=FALSE;
					DigitBin= PString();
				}

				OldOffHook = OffHook;
			}
		}

	        char digit = lidDevice()->ReadDTMF(0);

		if (digit != '\0') {
		   if (lidDevice()->GetDeviceType() == OpalLineInterfaceDevice::CellEmulate) { 
		      // Emulate Cell Phone behavior
			switch (digit) {
					  
			case 'A':    // Dial button
			   if (DigitBin.GetLength() > 0) {
			     cout << endl << "Placing Call to " << DigitBin << endl << flush;
			     lidDevice()->SetCallerID(0,DigitBin);
			     DigitBin = PString();
			     lidDevice()->PlayTone(0,OpalLineInterfaceDevice::RingTone);	
			     OnCallState = TRUE;
			    } 
			    break;

			case 'B':   // HangUp Button
			    if (OnCallState) {
				cout << "Call Ended." << endl << flush;
				OnCallState = FALSE;
				lidDevice()->StopTone(0);
			    } else {
				if (DigitBin.GetLength() > 0) {
				   DigitBin = PString();
				   cout << endl << "Clear Buffer.." << endl << flush;
				}
			     }
			     break;
					  
			case 'C':   // Menu Left
			     break;

			case 'D':   // Menu Right
			     break;

			default:
			    if (!OnCallState) {
			       DigitBin += digit;
			       cout << digit << flush;
			    } else {
				cout << "Sending " << digit << endl << flush;
			    }
			    lidDevice()->StopTone(0);
			}
	
		    } else if (lidDevice()->GetDeviceType() == OpalLineInterfaceDevice::POTSLine) {
		       // Emulate POTSLine Behavior
			if (digit != '#') {
			   if (OffHook) {
			     if (!OnCallState) {
				DigitBin += digit;
				cout << digit << flush;
			     } else {
				cout << "Sending " << digit << endl << flush;
			     }
				lidDevice()->StopTone(0);
			    }
			} else {
			    if (DigitBin.GetLength() > 0) {
				cout << endl << "Placing Call to " << DigitBin << endl << flush;
				lidDevice()->SetCallerID(0,DigitBin);
				DigitBin = PString();
				lidDevice()->PlayTone(0,OpalLineInterfaceDevice::RingTone);	
				OnCallState = TRUE;
			    } 
			}
		    } else {
		       // Treat as a Gateway
		    }
		}
	   }
	   monitorTickle.Wait(50);
	}
}