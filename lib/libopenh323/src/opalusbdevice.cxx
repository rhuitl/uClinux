/*
 * OpalUSBDevice.h
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
 * $Log: opalusbdevice.cxx,v $
 * Revision 1.4  2006/05/16 11:27:01  shorne
 * Added more key input support
 *
 * Revision 1.3  2005/11/21 20:55:56  shorne
 * Added support for more USB devices
 *
 * Revision 1.2  2005/08/23 08:42:24  shorne
 * silly little bug overlooked the first time
 *
 * Revision 1.1  2005/08/23 08:11:13  shorne
 * renamed to lower case
 *
 *
 *
*/

#include <ptlib.h>
#include <ptclib/dtmf.h>

#include "OpalUSBDevice.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

OpalUSBDevice::OpalUSBDevice()
{
    InputData = PluginHID_None;
	PluggedIn = FALSE;
	OffHookState = FALSE;
	digitbuffer = PString();

	soundDev = "USB Audio";   // This may change when device plugged in.
	useSound = FALSE;
    soundChannelBuffers = 5;
	PlaySound = NULL;
	RecSound = NULL;
	vol = 50;

	useTones = FALSE;
	ToneThread = NULL;

	isRinging = FALSE;
    exitFlag = FALSE;
	exitTone = TRUE;

	isCell = FALSE;
	hasPSTN = FALSE;
}

OpalUSBDevice::OpalUSBDevice(PluginHID_Definition * hid)
: HID(hid) 
{
    
	InputData = PluginHID_None;
	PluggedIn = FALSE;
	OffHookState = FALSE;
	digitbuffer = PString();

    soundDev = HID->sound;   // Temporary may change when device plugged in.

	soundChannelBuffers = 5;
	PlaySound = NULL;
	RecSound = NULL;
	SetPlayVolume(0,50);
	
	isRinging = FALSE;
	exitFlag = FALSE;
	exitTone = TRUE;

	ToneThread = NULL;

  switch (HID->flags & PluginHID_ToneMask) {
    case PluginHID_Tone:   // Tone generator required
      useTones = TRUE;
	  break;
    default:
	  useTones = FALSE;
      break;
  }

  switch (HID->flags & PluginHID_GatewayMask) {
    case PluginHID_PSTN:
      hasPSTN = TRUE;    // Supports PSTN Gateway
      break;
    default:
      hasPSTN = FALSE;
      break;
  }

  switch (HID->flags & PluginHID_DeviceTypeMask) {
    case PluginHID_DeviceCell:
      isCell = TRUE;    // behave like cell phone
      break;
    default:
      isCell = FALSE;
      break;
  }

  switch (HID->flags & PluginHID_DeviceSoundMask) {
    case PluginHID_DeviceSound:
      useSound = TRUE;	// use sound card
      break;
    default:
      useSound = FALSE;
      break;
  }
}

BOOL OpalUSBDevice::Open(
      const PString & /*device*/  /// Device identifier name.
    )
{
	
	MonitorThread = PThread::Create(PCREATE_NOTIFIER(Monitor), 0,
                            PThread::NoAutoDeleteThread,
                            PThread::NormalPriority,
                           "HIDMonitor:%x");
	return TRUE;
}

BOOL OpalUSBDevice::IsOpen() const
{
	return PluggedIn;
}

BOOL OpalUSBDevice::Close()
{
	if (PlaySound != NULL)
		delete PlaySound;

	if (RecSound != NULL)
		delete RecSound;

	PluggedIn= FALSE;
	exitFlag = TRUE;
	monitorTickle.Signal();
	MonitorThread->WaitForTermination();
	delete MonitorThread;

	return TRUE;
}

unsigned OpalUSBDevice::InvokeMessage(unsigned msg,unsigned val)
{
	PWaitAndSignal m(vbMutex);

    return (HID->HIDFunction)(HID,&msg, &val);
}

void OpalUSBDevice::Monitor(PThread &, INT)
{

int timeToWait;

  if (HID->destroyHID != NULL) 
	(HID->createHID)(HID);

	for (;;) {
		if (exitFlag)
			break;

		PWaitAndSignal m(vbMutex);
		InterpretInput((HID->HIDFunction)(HID,&InputData, 0));	
		InputData = PluginHID_None;

	   if (PluggedIn)
			timeToWait = 50;
	   else
			timeToWait = 500;

	   monitorTickle.Wait(timeToWait);
	}

	if (HID->destroyHID != NULL) 
	       (HID->destroyHID)(HID);
}

PString OpalUSBDevice::GetName() const
{
	return HID->descr + PString(" {usb}");
}

BOOL OpalUSBDevice::IsLineTerminal(
      unsigned line   /// Number of line
    )
{ 
	return line == POTSLine; 
}


BOOL OpalUSBDevice::IsLinePresent(
      unsigned line,      /// Number of line
      BOOL force		  /// Force test, do not optimise
    )
{
	return FALSE;
}

BOOL OpalUSBDevice::IsLineOffHook(
      unsigned line   /// Number of line
    )
{
	return OffHookState;
}


BOOL OpalUSBDevice::SetLineOffHook(
      unsigned line,        /// Number of line
      BOOL newState			/// New state to set
    )
{
	OffHookState = newState;
	return TRUE;
}

BOOL OpalUSBDevice::IsLineRinging(
      unsigned line,          /// Number of line
      DWORD * cadence		  /// Cadence of incoming ring
    )
{
	return isRinging;
}

BOOL OpalUSBDevice::RingLine(
      unsigned line,    /// Number of line
      DWORD cadence     /// Cadence bit map for ring pattern
    )
{
	if (cadence > 0) {
	InvokeMessage(PluginHID_StartRing);
	isRinging = TRUE;
	} else {
	InvokeMessage(PluginHID_StopRing);
	isRinging = FALSE;
	}
	return TRUE;
}

BOOL OpalUSBDevice::IsLineDisconnected(
      unsigned line,   /// Number of line
      BOOL checkForWink
    )
{
	return TRUE;
}

PINDEX OpalUSBDevice::GetReadFrameSize(
      unsigned line   /// Number of line
    )
{
	return MediaFormat.GetFrameSize();
}

BOOL OpalUSBDevice::SetReadFrameSize(unsigned, PINDEX)
{
	return TRUE;
}

PINDEX OpalUSBDevice::GetWriteFrameSize(
      unsigned line   /// Number of line
    )
{
	return MediaFormat.GetFrameSize();
}

BOOL OpalUSBDevice::SetWriteFrameSize(unsigned, PINDEX)
{
	return TRUE;
}

BOOL OpalUSBDevice::ReadFrame(
      unsigned line,    /// Number of line
      void * buf,       /// Pointer to a block of memory to receive data.
      PINDEX & count    /// Number of bytes read, <= GetReadFrameSize()
    )
{

	if ((RecSound ==NULL) || (!PluggedIn)) {
		PTRACE(3, "LID\tRead Device Unplugged.");
		return FALSE;
	}

	if (useSound) {
	    RecSound->Read(buf,count);
	} else {

	}
	count = RecSound->GetLastReadCount();
	return TRUE;
}

BOOL OpalUSBDevice::WriteFrame(
      unsigned line,    /// Number of line
      const void * buf, /// Pointer to a block of memory to write.
      PINDEX count,     /// Number of bytes to write, <= GetWriteFrameSize()
      PINDEX & written  /// Number of bytes written, <= GetWriteFrameSize()
    )
{

	if ((PlaySound == NULL) || (!PluggedIn)) {
        PTRACE(3, "LID\tWrite Device Unplugged.");
		return FALSE;
	}

    if (useSound) {
        PlaySound->Write(buf, count);
	} else {

	}
	written = PlaySound->GetLastWriteCount();

	return TRUE;
}

BOOL OpalUSBDevice::SetRecordVolume(
      unsigned line,    /// Number of line
      unsigned volume   /// Volume level from 0 to 100%
    )
{
	if (volume < 0)
      volume = 0;
    else if (volume > 100)
      volume = 100;
 
	int volVal = volume | (volume << 8);
	InvokeMessage(PluginHID_SetRecVol,volVal);

	return TRUE;
}

BOOL OpalUSBDevice::SetPlayVolume(
      unsigned line,    /// Number of line
      unsigned volume   /// Volume level from 0 to 100%
    )
{
	vol = volume;

    if (vol < 0)
      vol = 0;
    else if (vol > 100)
      vol = 100;

	int volVal = vol | (vol << 8);
	InvokeMessage(PluginHID_SetPlayVol,volVal);

	return TRUE;
}

BOOL OpalUSBDevice::GetRecordVolume(
      unsigned line,      /// Number of line
      unsigned & volume   /// Volume level from 0 to 100%
    )
{
	volume = InvokeMessage(PluginHID_GetRecVol); 
	volume &= 0xff;

	if (volume > 100)
		volume = (unsigned)0;
	return TRUE;
}

BOOL OpalUSBDevice::GetPlayVolume(
      unsigned line,      /// Number of line
      unsigned & volume   /// Volume level from 0 to 100%
    )
{
	volume = InvokeMessage(PluginHID_GetPlayVol);
	volume &= 0xff;

	if (volume > 100)
		volume = (unsigned)0;
	return TRUE;
}

BOOL OpalUSBDevice::PlayDTMF(
      unsigned line,            /// Number of line
      const char * digits,      /// DTMF digits to be played
      DWORD onTime,				/// Number of milliseconds to play each DTMF digit
      DWORD offTime				/// Number of milliseconds between digits
    )
{


#ifdef _WIN32
  const PString & dev = soundDev;

	PString Digits = digits;

	for (PINDEX i = 0; i < Digits.GetLength(); i++) {
          // Some USB devices have Tone generator for digit press
          // however do not have ability to play tones so we allocate 
          // Line 1 to specify we are playing tones on sending input etc
		if ((useTones) || (line == 1)) {
			PDTMFEncoder encoder;
			encoder.AddTone(Digits[i]);
			PSound soundtone(1, 8000, 16, encoder.GetSize(),encoder.GetPointer());

			if (!soundtone.Play(dev)) {
				  PTRACE(3, "LID\tError Opening " << dev << " for DTMF Tone.");
					return FALSE;
			}
		} else {
			return FALSE;	    
		}
	}
#endif

	return TRUE;
}

char OpalUSBDevice::ReadDTMF(
      unsigned line   /// Number of line
    )
{
	if (digitbuffer.GetLength() > 0) {
		char ret = digitbuffer[0];
		digitbuffer = digitbuffer.Right(digitbuffer.GetLength()-1);
		return ret;
	} else {
		return '\0';
	}
}

BOOL OpalUSBDevice::PlayTone(
      unsigned line,          /// Number of line
      CallProgressTones tone  /// Tone to be played
    )
{
	// Stop Current Tones
	StopTone(0);

	CurTone = tone;
	// Create a Tone Thread.
	exitTone = FALSE;
	ToneThread = PThread::Create(PCREATE_NOTIFIER(TonePlay), 0,
			PThread::NoAutoDeleteThread,PThread::NormalPriority,
			"HIDTone:%x");
	return TRUE;
}

BOOL OpalUSBDevice::IsTonePlaying(
      unsigned line   /// Number of line
    )
{
	return (!exitTone);
}

BOOL OpalUSBDevice::StopTone(
      unsigned line   /// Number of line
    )
{
    InvokeMessage(PluginHID_StopRing);
	isRinging = FALSE;

	if (ToneThread != NULL) {
	   exitTone = TRUE;
	   ToneThread->Terminate();
           ToneThread->WaitForTermination();
	   delete ToneThread;
	   ToneThread = NULL;
	}
	
	return TRUE;
}

unsigned OpalUSBDevice::GetLineCount()
{
	return 0;
}

OpalMediaFormat::List OpalUSBDevice::GetMediaFormats() const
{
  OpalMediaFormat::List formats;

  return formats;
}

BOOL OpalUSBDevice::SetReadFormat(unsigned line, const OpalMediaFormat &mediaFormat)
{

	MediaFormat = mediaFormat;
	PINDEX samplesPerFrame = (mediaFormat.GetFrameTime() * mediaFormat.GetTimeUnits()) / 8;
	unsigned rate = mediaFormat.GetTimeUnits() * 1000;

	if (useSound) {
		CreateSoundDevice(TRUE,soundDev,rate,samplesPerFrame);
	} else {

	}

	return TRUE;
}

BOOL OpalUSBDevice::SetWriteFormat(unsigned line,const OpalMediaFormat &mediaFormat)
{

	MediaFormat = mediaFormat;
	PINDEX samplesPerFrame = (mediaFormat.GetFrameTime() * mediaFormat.GetTimeUnits()) / 8;
	unsigned rate = mediaFormat.GetTimeUnits() * 1000;

	if (useSound) {
		CreateSoundDevice(FALSE,soundDev,rate,samplesPerFrame);
	} else {

	}

	return TRUE;
}

OpalMediaFormat OpalUSBDevice::GetReadFormat(unsigned line)
{
	return MediaFormat;
}

OpalMediaFormat OpalUSBDevice::GetWriteFormat(unsigned line)
{
	return MediaFormat;
}

BOOL OpalUSBDevice::GetCallerID(
      unsigned line,      /// Number of line
      PString & idString, /// ID string returned
      BOOL full		      /// Get full information in idString
    )
{
	return FALSE;
}

BOOL OpalUSBDevice::SetCallerID(
      unsigned line,            /// Number of line
      const PString & idString  /// ID string to use
    )
{
	(HID->displayHID)(HID, (const char *)idString);
	return TRUE;
}

OpalLineInterfaceDevice::DeviceType OpalUSBDevice::GetDeviceType()
{ 
   if (isCell)	
	   return OpalLineInterfaceDevice::CellEmulate;

   if (hasPSTN)
	   return OpalLineInterfaceDevice::Gateway;

	return OpalLineInterfaceDevice::POTSLine; 

}


BOOL OpalUSBDevice::StopReadCodec(unsigned line)
{
	delete RecSound;
	RecSound = NULL;
	return TRUE;
}


BOOL OpalUSBDevice::StopWriteCodec(unsigned line)
{
	delete PlaySound;
	PlaySound = NULL;
	return TRUE;
}

BOOL LoadSoundDevice(PString & dev,PString devstr)
{

  /// have to put something in here to clear out the sound device cache.
  /// The device cache is created when the H323Endpoint is created and if 
  /// the USB device is not plugged in at startup it will not detected when plugging
  /// the device in...


  /// Some Windows versions shows different names for USB Audio devices
      PStringArray devices = PSoundChannel::GetDeviceNames(PSoundChannel::Player);
      for (PINDEX i = 0; i < devices.GetSize(); i++) {
        if (devices[i] == devstr)
			break;
        if (devices[i].Find(devstr) != P_MAX_INDEX) {
			dev = devices[i];
			break;
		}
	  }

	return TRUE;
}


void OpalUSBDevice::InterpretInput(unsigned int ret)
{
   if (ret == PluginHID_None)
	   return;

	 switch (ret) {
	 case PluginHID_Key1:
			digitbuffer += "1";
			PlayDTMF(0,"1");
			break;
	 case PluginHID_Key2:
			digitbuffer += "2";
			PlayDTMF(0,"2");
			break;
	 case PluginHID_Key3:
			digitbuffer += "3";
			PlayDTMF(0,"3");
			break;
	 case PluginHID_Key4:
			digitbuffer += "4";
			PlayDTMF(0,"4");
			break;
	 case PluginHID_Key5:
			digitbuffer += "5";
			PlayDTMF(0,"5");
			break;
	 case PluginHID_Key6:
			digitbuffer += "6";
			PlayDTMF(0,"6");
			break;
	 case PluginHID_Key7:
			digitbuffer += "7";
			PlayDTMF(0,"7");
			break;
	 case PluginHID_Key8:
			digitbuffer += "8";
			PlayDTMF(0,"8");
			break;
	 case PluginHID_Key9:
			digitbuffer += "9";
			PlayDTMF(0,"9");
			break;
	 case PluginHID_Key0:
			digitbuffer += "0";
			PlayDTMF(0,"0");
			break;
	 case PluginHID_KeyStar:
			digitbuffer += "*";
			PlayDTMF(0,"*");
			break;
	 case PluginHID_KeyHash:
			digitbuffer += "#";
			PlayDTMF(0,"#");
			break;
	 case PluginHID_KeyA:
			digitbuffer += "A";
			PlayDTMF(0,"A");
			break;
	 case PluginHID_KeyB:
			digitbuffer += "B";
			PlayDTMF(0,"B");
			break;
	 case PluginHID_KeyC:
			digitbuffer += "C";
			PlayDTMF(0,"C");
			break;
	 case PluginHID_KeyD:
			digitbuffer += "D";
			PlayDTMF(0,"D");
			break;
	 case PluginHID_OffHook:
		        OffHookState = TRUE;
			break;
	 case PluginHID_OnHook:
			OffHookState = FALSE;
			break;
	 case PluginHID_VolumeUp:
		        vol += 5;
			SetPlayVolume(0, vol);
		    break;
	 case PluginHID_VolumeDown:
		        vol += -5;
			SetPlayVolume(0, vol);
			break;
	 case PluginHID_PluggedIn:
		    LoadSoundDevice(soundDev,soundDev);
			PluggedIn = TRUE;
			break;
	 case PluginHID_Unplugged:
			PluggedIn = FALSE;
			break;
	 case PluginHID_Redial:
            break;
	 case PluginHID_UpButton:
		    break;
	 case PluginHID_DownButton:
		    break;
	}

}

BOOL OpalUSBDevice::CreateSoundDevice(BOOL IsEncoder,
					const PString & device, 
					PINDEX rate, 
					PINDEX samples)
{

	if (IsEncoder) {

		if (RecSound != NULL) {
		  delete RecSound;
		  RecSound = NULL;
		}
		RecSound = new PSoundChannel;
		if (RecSound->Open(device,PSoundChannel::Recorder,1,rate,16)) {
			RecSound->SetBuffers(samples*2, soundChannelBuffers);
		} else {
                    PTRACE(3, "LID\tError Opening Record Device.");
			return FALSE;
		}

	} else {
		if (PlaySound != NULL) {
		  delete PlaySound;
		  PlaySound = NULL;
	         }
		PlaySound = new PSoundChannel;

		if (PlaySound->Open(device,PSoundChannel::Player,1,rate,16)) {
			PlaySound->SetBuffers(samples*2, soundChannelBuffers);
			PlaySound->SetVolume(vol);
		} else {
                    PTRACE(3, "LID\tError Opening Play Device.");
			return FALSE;
		}
	}

	return TRUE;
}

void OpalUSBDevice::TonePlay(PThread &, INT)
{

    PDTMFEncoder encoder;

	switch (CurTone) {
		case DialTone:
			encoder.GenerateDialTone();
			break;
		case RingTone:
			encoder.GenerateRingBackTone();
			break;
		case BusyTone:
			encoder.GenerateBusyTone();
			break;
	}

	SoundTones soundtone(1, 8000, 16, encoder.GetSize(),encoder.GetPointer());

	soundtone.RunContinuous(this);

}

///////////////////////////////////////////////////////////////////////
// Sound Tones

OpalUSBDevice::SoundTones::SoundTones(unsigned channels,
               unsigned samplesPerSecond,
               unsigned bitsPerSample,
               PINDEX   bufferSize,
               const BYTE * buffer)
: PSound(channels,samplesPerSecond,bitsPerSample,bufferSize,buffer)
{
}

void OpalUSBDevice::SoundTones::RunContinuous(OpalUSBDevice * dev) const
{
	PSoundChannel channel(dev->soundDev, PSoundChannel::Player);
	
	if (channel.IsOpen()) {
		for (;;) {
			if (dev->exitTone)
				break;	

			channel.PlaySound(*this, TRUE);
		}
	} else {
		PTRACE(3, "LID\tError Opening " << dev << " for Tone Play.");
	}
}

