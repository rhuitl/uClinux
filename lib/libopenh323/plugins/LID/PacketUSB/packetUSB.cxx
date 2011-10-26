/* 
 * packetUSB.cxx
 *
 * Packetizer USB Phone for OpenH323/OPAL
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
 * $Log: packetUSB.cxx,v $
 * Revision 1.3  2005/09/01 06:40:35  shorne
 * added check to see if device is plugged in before adjusting volumes.
 *
 * Revision 1.2  2005/08/23 07:32:59  shorne
 * Greatly simplified plugin / added volume support
 *
 *
*/

#include "packetUSB.h"
#include "packetUSB/CM_HID.h"

#include <string>    
using std::string; 

LRESULT WinProc(HWND hwnd,UINT uMsg,WPARAM wParam,LPARAM lParam);//Window CallBack Procedure

#pragma comment(lib,"packetUSB/CM_HID.lib")			// HID Library

// SubClass Values
#define WM_HID_DEV_ADDED      WM_USER+0x1000
#define WM_HID_DEV_REMOVED    WM_USER+0x1001
#define WM_HID_KEY_DOWN       WM_USER+0x1002
#define WM_HID_KEY_UP         WM_USER+0x1003
#define WM_HID_VOLUME_DOWN    WM_USER+0x1004
#define WM_HID_VOLUME_UP      WM_USER+0x1005
#define WM_HID_PLAYBACK_MUTE  WM_USER+0x1006
#define WM_HID_RECORD_MUTE    WM_USER+0x1007


unsigned int InputFlag = PluginHID_None;    // Input Flag
HINSTANCE hInstance=NULL;					// Module Instance
HWND m_hWnd = NULL;
BOOL pluggedIn = FALSE;

unsigned int InputFlagAssign(int inputvalue)
{

	switch (inputvalue) {
		case 1:
			return PluginHID_Key1;
		case 2:
			return PluginHID_Key4;
		case 3:
			return PluginHID_Key7;
		case 4:
			return PluginHID_KeyStar;  // Star key
		case 5:
			return PluginHID_Key2;
		case 6:
			return PluginHID_Key5;
		case 7:
			return PluginHID_Key8;
		case 8:
			return PluginHID_Key0;
		case 9:
			return PluginHID_Key3;
		case 10:
			return PluginHID_Key6;
		case 11:
			return PluginHID_Key9;
		case 12:
			return PluginHID_KeyHash;  // Hash Key
		case 13:
			return PluginHID_KeyA;  // Dial key
		case 14:
			return PluginHID_KeyB;  // Stop Dial key
		case 15:
			return PluginHID_KeyC;  // left Navigator Keys
		case 16:
			return PluginHID_KeyD;  // Right Navigator Keys
		default:
			return 0;
	}
}


LRESULT WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) 
{
	// TODO: Add your specialized code here and/or call the base class

    switch(message)
    {
    case WM_HID_DEV_ADDED: 
		InputFlag = PluginHID_PluggedIn;
		pluggedIn = TRUE;
        StartKeyScan();
        break;

    case WM_HID_DEV_REMOVED: 
		InputFlag = PluginHID_Unplugged;
		pluggedIn = FALSE;
        StopKeyScan();
        break;

    case WM_HID_KEY_DOWN: 
		InputFlag = InputFlagAssign((int)wParam);
        break;

    case WM_HID_KEY_UP: 
 // Do Nothing
        break;

    case WM_HID_VOLUME_DOWN: 
		if ((int)wParam == 1)
		  InputFlag = PluginHID_VolumeUp;
		else
		  InputFlag = PluginHID_VolumeDown;
        break;

    case WM_HID_VOLUME_UP: 
  // Do Nothing
        break;

    case WM_HID_PLAYBACK_MUTE: 
  //  Not Implemented

        break;

    case WM_HID_RECORD_MUTE: 
 //   Not Implemented
        break;

    case WM_DEVICECHANGE: 
        HandleUsbDeviceChange(wParam, lParam); 
        break;

	default:
		InputFlag = message;
    }
	
	return DefWindowProc(hWnd, message, wParam, lParam);
}

bool InitialiseHID()
{

const char * classname = "CM_HID";	 

WNDCLASS wc;
  
	if (m_hWnd == NULL) {

		// Register the main window class. 
		wc.style = CS_GLOBALCLASS | CS_HREDRAW | CS_VREDRAW; 
		wc.lpfnWndProc = (WNDPROC)WndProc; 
		wc.cbClsExtra = 0; 
		wc.cbWndExtra = 0; 
		wc.hInstance = hInstance; 
		wc.hIcon = LoadIcon(NULL, IDI_APPLICATION); 
		wc.hCursor = LoadCursor(NULL, IDC_ARROW); 
		wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1); 
		wc.lpszMenuName =  NULL; 
		wc.lpszClassName = classname; 
 
		if (!RegisterClass(&wc)) 
		   return FALSE; 

		m_hWnd= CreateWindowEx(0,
			classname,
			classname,
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT, 
			CW_USEDEFAULT,
			200,
			150,
			0,
			0,
			hInstance,
			0);	
	}

	if (m_hWnd == NULL) 
		return FALSE;

	StartDeviceDetection(m_hWnd, WM_HID_DEV_ADDED, WM_HID_DEV_REMOVED,
	WM_HID_KEY_DOWN, WM_HID_KEY_UP, WM_HID_VOLUME_DOWN, WM_HID_VOLUME_UP,
	WM_HID_PLAYBACK_MUTE, WM_HID_RECORD_MUTE);

	return TRUE;
	
}



bool SetVolume(DWORD inout, DWORD ComponentType, DWORD dwVol)
{
	if (!pluggedIn)
		return FALSE;

	UINT dev = mixerGetNumDevs();
	UINT devNo = 0;

	if (dev > 1) {
		MIXERCAPS caps;
		for(UINT j = 0; j < dev; j++){
			mixerGetDevCaps(j, &caps, sizeof(caps));
			string device = caps.szPname;
			if (device.find("USB Audio",0) != -1) {
				devNo = j;
				break;
			}
		}
	}

	HMIXER hMixer;
	HRESULT hr;
	hr = mixerOpen(&hMixer, devNo, 0, 0, 0);
	if (FAILED(hr)) false;
	
	MIXERLINE mxl;
	MIXERCONTROL mc;
	MIXERLINECONTROLS mxlc;
	MIXERCONTROLDETAILS mxcd;
	MIXERCONTROLDETAILS_UNSIGNED mxdu;
	DWORD count, armxdu[2];
	
	memset(&mxl, 0, sizeof(mxl));
	mxl.cbStruct = sizeof(mxl);
	mxl.dwComponentType = inout;
	
    hr = mixerGetLineInfo((HMIXEROBJ)hMixer, &mxl, MIXER_GETLINEINFOF_COMPONENTTYPE);
	if (FAILED(hr) || mxl.cControls == 0)
	{
		mixerClose(hMixer);
		return false;
	}
	
	count = mxl.cConnections;
	if(count == (UINT) -1)
	{
		mixerClose(hMixer);
		return false;
	}
	
	for(UINT i = 0; i < count; i++)
	{
		mxl.dwSource = i;
		mixerGetLineInfo((HMIXEROBJ)hMixer, &mxl, MIXER_GETLINEINFOF_SOURCE);
		if (mxl.dwComponentType == ComponentType)
		{
			mc.cbStruct = sizeof(mc);
			mxlc.cbStruct = sizeof(mxlc);
			mxlc.dwLineID = mxl.dwLineID;
			mxlc.dwControlType = MIXERCONTROL_CONTROLTYPE_VOLUME;
			mxlc.cControls = 1;
			mxlc.cbmxctrl = sizeof(MIXERCONTROL);
			mxlc.pamxctrl = &mc;
			hr = mixerGetLineControls((HMIXEROBJ)hMixer, &mxlc, MIXER_GETLINECONTROLSF_ONEBYTYPE);
			// setting value
			for(UINT i=0; i<(mxl.cChannels); i++)
				armxdu[i]=dwVol;
			mxdu.dwValue = dwVol;
			mxcd.cMultipleItems = 0;
			mxcd.cChannels = mxl.cChannels;
			mxcd.cbStruct = sizeof(mxcd);
			mxcd.dwControlID = mc.dwControlID;
			mxcd.cbDetails = sizeof(armxdu);
			mxcd.paDetails = &armxdu;
			hr = mixerSetControlDetails((HMIXEROBJ)hMixer, &mxcd, MIXER_SETCONTROLDETAILSF_VALUE);	
			break;
		}
	}
	mixerClose(hMixer);
	return true;
}

DWORD GetVolume(DWORD inout, DWORD ComponentType)
{
	if (!pluggedIn)
		return -1;

	UINT dev = mixerGetNumDevs();
	UINT devNo = 0;

	if (dev > 1) {
		MIXERCAPS caps;
		for(UINT j = 0; j < dev; j++){
			mixerGetDevCaps(j, &caps, sizeof(caps));
			string device = caps.szPname;
			if (device.find("USB Audio",0) != -1) {
				devNo = j;
				break;
			}
		}
	}

	HMIXER hMixer;
	HRESULT hr;

	hr = mixerOpen(&hMixer, devNo, 0, 0, 0);
	if (FAILED(hr))
	{
		return -1;
	}
	
	MIXERLINE mxl;
	MIXERCONTROL mc;
	MIXERLINECONTROLS mxlc;
	MIXERCONTROLDETAILS mxcd;
	MIXERCONTROLDETAILS_UNSIGNED mxdu;
	DWORD count, armxdu[]={0L, 0L};
	
	memset(&mxl, 0, sizeof(mxl));
	mxl.cbStruct = sizeof(mxl);
	mxl.dwComponentType = inout /*ComponentType*/;
	mxdu.dwValue = -1;	// default
	
    hr = mixerGetLineInfo((HMIXEROBJ)hMixer, &mxl, MIXER_GETLINEINFOF_COMPONENTTYPE);
	if (FAILED(hr) || mxl.cControls==0)
	{
		mixerClose(hMixer);
		return -1;
	}
	
	count = mxl.cConnections/* dwSource*/;
	if(count == (UINT)-1)
	{
		mixerClose(hMixer);
		return -1;
	}

	for(UINT i = 0; i < count; i++)
	{
		mxl.dwSource = i;

		hr = mixerGetLineInfo((HMIXEROBJ)hMixer, &mxl, MIXER_GETLINEINFOF_SOURCE);
		if ((!FAILED(hr)) && (mxl.dwComponentType == ComponentType))
		{
			mc.cbStruct = sizeof(mc);
			mxlc.cbStruct = sizeof(mxlc);
			mxlc.dwLineID = mxl.dwLineID;
			mxlc.dwControlType = MIXERCONTROL_CONTROLTYPE_VOLUME;
			mxlc.cControls = 1;
			mxlc.cbmxctrl = sizeof(MIXERCONTROL);
			mxlc.pamxctrl = &mc;
			
			hr = mixerGetLineControls((HMIXEROBJ)hMixer, &mxlc, MIXER_GETLINECONTROLSF_ONEBYTYPE);
			if(FAILED(hr))
					continue;

			// getting value
			mxcd.cMultipleItems = 0;
			mxcd.cChannels = mxl.cChannels;
			mxcd.cbStruct = sizeof(mxcd);
			mxcd.dwControlID = mc.dwControlID;
			mxcd.cbDetails = sizeof(mxdu);
			mxcd.paDetails = &mxdu;
			hr = mixerGetControlDetails((HMIXEROBJ)hMixer, &mxcd, MIXER_GETCONTROLDETAILSF_VALUE);	
			if(FAILED(hr))
				   continue;

			break;
		}
	}
	mixerClose(hMixer);

	return mxdu.dwValue;
}

///////////////////////////////////////////////////////////////////////////////////////////////

static void * create_HID(const struct PluginHID_Definition * hid)
{

    return (void *)InitialiseHID(); 
}

static void destroy_HID(const struct PluginHID_Definition * hid)
{
	StopKeyScan();
	DestroyWindow(m_hWnd);
}

static unsigned int HID_Function(const struct PluginHID_Definition * hid, unsigned int * InputMask, unsigned int * newVal)
{

 switch (*InputMask) {
	case PluginHID_StartRing:
		StartBuzzer();
		return 0;

	case PluginHID_StopRing:
		StopBuzzer();
		return 0;

	case PluginHID_SetRecVol:
		return SetVolume(MIXERLINE_COMPONENTTYPE_DST_WAVEIN,
			MIXERLINE_COMPONENTTYPE_SRC_MICROPHONE,(DWORD)*newVal);

	case PluginHID_GetRecVol:
		return GetVolume(MIXERLINE_COMPONENTTYPE_DST_WAVEIN,
			MIXERLINE_COMPONENTTYPE_SRC_MICROPHONE);
				
	case PluginHID_SetPlayVol:
		return SetVolume(MIXERLINE_COMPONENTTYPE_DST_SPEAKERS ,
			MIXERLINE_COMPONENTTYPE_SRC_WAVEOUT, (DWORD)*newVal);

	case PluginHID_GetPlayVol:
		return GetVolume(MIXERLINE_COMPONENTTYPE_DST_SPEAKERS,
			MIXERLINE_COMPONENTTYPE_SRC_WAVEOUT);
 }

 	MSG msg;
	BOOL bRet;
	DWORD idThread = GetCurrentThreadId();

	if (!PostThreadMessage(idThread, WM_COMMAND, (WPARAM)0, (LPARAM)0))
			return 0;

	bRet = GetMessage( &msg, NULL, 0, 0 );
	 
	if (bRet > 0) {
		if (msg.message != WM_QUIT) 	{
			TranslateMessage( &msg );
			DispatchMessage( &msg );
		}
	}
	

    unsigned int retval = InputFlag;
	InputFlag = PluginHID_None;
  return retval; 
}

static void display_HID(const struct PluginHID_Definition * def, const char * display)
{
// Not Used
}
///////////////////////////////////////////////////////////////////////////////////////////////

static struct PluginHID_Definition HIDDefn[] = {
  DECLARE_PARAM(PacketUSB)
};

#define NUM_DEFNS   (sizeof(HIDDefn) / sizeof(struct PluginHID_Definition))


extern "C" {

PLUGIN_CODEC_DLL_API struct PluginHID_Definition * PLUGIN_HID_GET_DEVICE_FN(unsigned * count, unsigned version)
{
  *count = NUM_DEFNS;
  return HIDDefn;	
}

};

