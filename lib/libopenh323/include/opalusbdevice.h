/*
 * opalusbdevice.h
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
 * $Log: opalusbdevice.h,v $
 * Revision 1.1  2005/08/23 08:11:59  shorne
 * renamed file to lower case
 *
 *
 *
*/

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "openh323buildopts.h"

#include <lid.h>
#include <opalplugin.h>


#ifdef _MSC_VER
#pragma warning(disable:4100)
#endif

/* Line Interface device Implementation for USB Plugin devices.
*/
class OpalUSBDevice : public OpalLineInterfaceDevice
{

   PCLASSINFO(OpalUSBDevice, OpalLineInterfaceDevice);

public:

	class SoundTones : public PSound
	{
	public:
		SoundTones(unsigned channels,
               unsigned samplesPerSecond,
               unsigned bitsPerSample,
               PINDEX   bufferSize,
               const BYTE * buffer);

		void RunContinuous(OpalUSBDevice * dev) const;
	};

    /**Create a new, closed, device for a USB Hardware device.
      */
	OpalUSBDevice();

	OpalUSBDevice(PluginHID_Definition * hid);

	~OpalUSBDevice() { Close(); };

    /**Open and detect USB device.
      */
    virtual BOOL Open(
      const PString & device  /// Device identifier name.
    );

    /**Determine if the line interface device is plugged in.
      */
    virtual BOOL IsOpen() const;

    /**Close the USB device.
      */
    virtual BOOL Close();

    /**Get the device name.
      */
    virtual PString GetName() const;

    /**Get the type of the line.
      */
    virtual BOOL IsLineTerminal(
      unsigned line   /// Number of line
    );

    enum {
      POTSLine,
      PSTNLine,
      NumLines
    };

    /**Determine if a physical line is present on the logical line.
      */
    virtual BOOL IsLinePresent(
      unsigned line,      /// Number of line
      BOOL force = FALSE  /// Force test, do not optimise
    );


    /**Determine if line is currently off hook.
       This returns TRUE if GetLineState() is a state that implies the line is
       off hook (eg OffHook or LineBusy).
      */
    virtual BOOL IsLineOffHook(
      unsigned line   /// Number of line
    );

    /**Set the state of the line.
       Note that not be possible on a given line.
      */
    virtual BOOL SetLineOffHook(
      unsigned line,        /// Number of line
      BOOL newState = TRUE  /// New state to set
    );


    /**Determine if line is ringing.
      */
    virtual BOOL IsLineRinging(
      unsigned line,          /// Number of line
      DWORD * cadence = NULL  /// Cadence of incoming ring
    );

    /**Begin ringing local phone set with specified cadence.
       If cadence is zero then stops ringing.
      */
    virtual BOOL RingLine(
      unsigned line,    /// Number of line
      DWORD cadence     /// Cadence bit map for ring pattern
    );

    /**Determine if line has been disconnected from a call.
      */
    virtual BOOL IsLineDisconnected(
      unsigned line,   /// Number of line
      BOOL checkForWink = TRUE
    );

    /**Get the read frame size in bytes.
       All calls to ReadFrame() will return this number of bytes.
      */
    virtual PINDEX GetReadFrameSize(
      unsigned line   /// Number of line
    );

    virtual BOOL SetReadFrameSize(unsigned, PINDEX);

    /**Get the write frame size in bytes.
       All calls to WriteFrame() must be this number of bytes.
      */
    virtual PINDEX GetWriteFrameSize(
      unsigned line   /// Number of line
    );

    virtual BOOL SetWriteFrameSize(unsigned, PINDEX);


    /**Low level read of a frame from the device.
     */
    virtual BOOL ReadFrame(
      unsigned line,    /// Number of line
      void * buf,       /// Pointer to a block of memory to receive data.
      PINDEX & count    /// Number of bytes read, <= GetReadFrameSize()
    );

    /**Low level write frame to the device.
     */
    virtual BOOL WriteFrame(
      unsigned line,    /// Number of line
      const void * buf, /// Pointer to a block of memory to write.
      PINDEX count,     /// Number of bytes to write, <= GetWriteFrameSize()
      PINDEX & written  /// Number of bytes written, <= GetWriteFrameSize()
    );

   /**Set volume level for recording.
       A value of 100 is the maximum volume possible for the hardware.
       A value of 0 is the minimum volume possible for the hardware.
      */
    virtual BOOL SetRecordVolume(
      unsigned line,    /// Number of line
      unsigned volume   /// Volume level from 0 to 100%
    );

    /**Set volume level for playing.
       A value of 100 is the maximum volume possible for the hardware.
       A value of 0 is the minimum volume possible for the hardware.
      */
    virtual BOOL SetPlayVolume(
      unsigned line,    /// Number of line
      unsigned volume   /// Volume level from 0 to 100%
    );

    /**Get volume level for recording.
       A value of 100 is the maximum volume possible for the hardware.
       A value of 0 is the minimum volume possible for the hardware.
      */
    virtual BOOL GetRecordVolume(
      unsigned line,      /// Number of line
      unsigned & volume   /// Volume level from 0 to 100%
    );

    /**Set volume level for playing.
       A value of 100 is the maximum volume possible for the hardware.
       A value of 0 is the minimum volume possible for the hardware.
      */
    virtual BOOL GetPlayVolume(
      unsigned line,      /// Number of line
      unsigned & volume   /// Volume level from 0 to 100%
    );

    /**Play a DTMF digit.
       Any characters that are not in the set 0-9, A-D, * or # will be ignored.
      */
    virtual BOOL PlayDTMF(
      unsigned line,            /// Number of line
      const char * digits,      /// DTMF digits to be played
      DWORD onTime = DefaultDTMFOnTime,  /// Number of milliseconds to play each DTMF digit
      DWORD offTime = DefaultDTMFOffTime /// Number of milliseconds between digits
    );


    /**Read a DTMF digit detected.
       This may be characters from the set 0-9, A-D, * or #. A null ('\0')
       character indicates that there are no tones in the queue.

      */
    virtual char ReadDTMF(
      unsigned line   /// Number of line
    );

    /**Play a tone.
      */
    virtual BOOL PlayTone(
      unsigned line,          /// Number of line
      CallProgressTones tone  /// Tone to be played
    );

    /**Determine if a tone is still playing
      */
    virtual BOOL IsTonePlaying(
      unsigned line   /// Number of line
    );

    /**Stop playing a tone.
      */
    virtual BOOL StopTone(
      unsigned line   /// Number of line
    );

    /**Get Caller ID from the last incoming ring.
       The idString parameter is either simply the "number" field of the caller
       ID data, or if full is TRUE, all of the fields in the caller ID data.

       The full data of the caller ID string consists of the number field, the
       time/date and the name field separated by tabs ('\t').
      */
    virtual BOOL GetCallerID(
      unsigned line,      /// Number of line
      PString & idString, /// ID string returned
      BOOL full = FALSE   /// Get full information in idString
    );

    /**Set Caller ID for use in next RingLine() call.
       The full data of the caller ID string consists of the number field, the
       time/date and the name field separated by tabs ('\t').

       If the date field is missing (two consecutive tabs) then the current
       time and date is used. Using an empty string will clear the caller ID
       so that no caller ID is sent on the next RingLine() call.
      */
    virtual BOOL SetCallerID(
      unsigned line,            /// Number of line
      const PString & idString  /// ID string to use
    );

	/** Get Line Count. At resent this returns 0
	  */
	virtual unsigned GetLineCount();

	/** GetMedia Formats
	  */
	virtual OpalMediaFormat::List GetMediaFormats() const;

	/** Set Read Frame size
	  */
	virtual BOOL SetReadFormat(unsigned line, const OpalMediaFormat &mediaFormat);

	/** Set write Frame size
	  */
	virtual SetWriteFormat(unsigned line,const OpalMediaFormat &mediaFormat);

	/** Get the Read format
	  */
	virtual OpalMediaFormat GetReadFormat(unsigned line);

	/** Get the Write Format
	  */
	virtual OpalMediaFormat GetWriteFormat(unsigned line);

    /**Stop the read codec.
      */
    virtual BOOL StopReadCodec(
      unsigned line   /// Number of line
    );

    /**Stop the write codec.
      */
    virtual BOOL StopWriteCodec(
      unsigned line   /// Number of line
    );

	/** Get Device Type
	  */
    virtual OpalLineInterfaceDevice::DeviceType GetDeviceType();

    PString soundDev;									/// Sound DeviceName
	BOOL exitTone;										/// Exit Tone Thread Flag

protected:

	/** Interpret input received from the HID
	  */
	void InterpretInput(unsigned int ret);

	/* Create the Sound Device (Usually a specific soundcard ie "USB Audio Device")
	 */
	BOOL CreateSoundDevice(BOOL IsEncoder,
			       const PString & device, 
			       PINDEX rate = 8000,
			       PINDEX samples = 1
			       );

	OpalMediaFormat MediaFormat;

	/* Invoke a message to the USB HID
	 */
	unsigned int InvokeMessage(unsigned msg,unsigned val=0);

	PluginHID_Definition * HID;							/// HID Definition from the Plugin

	PThread  *  MonitorThread;							/// Monitor Thread. 
	PSyncPoint monitorTickle;							/// Poll wait
    PDECLARE_NOTIFIER(PThread, OpalUSBDevice, Monitor); /// Declaration of the Thread
	BOOL exitFlag;										/// Exit Thread Monitor Flag

	BOOL PluggedIn;										/// Device plugged in
	unsigned int InputData;								/// Data sent to the USB Phone	
	PString digitbuffer;								/// Digit Buffer from USB Phone
	BOOL OffHookState;									/// Hook state	
	BOOL isRinging;										/// Whether the device is ringing			

	//Sound Channels & Settings
	BOOL useSound;										/// Flag to specify is Regular Sound device
	PSoundChannel * RecSound;							/// Sound Record Channel
	PSoundChannel * PlaySound;							/// Sound Play Channel
	PINDEX soundChannelBuffers;							/// Sound Channel Buffers
	PINDEX vol;											/// Current Speaker volume

	// Tone Generator
	BOOL useTones;										/// Tones required.
	CallProgressTones CurTone;							/// Current Tone to Play
	PThread  *  ToneThread;							    /// Tone Thread. 
    PDECLARE_NOTIFIER(PThread, OpalUSBDevice, TonePlay); /// Declaration of the ToneThread
	PMutex vbMutex;										/// Mute

	// Gateway
	BOOL hasPSTN;

	// behaviour
	BOOL isCell;

};


//#endif
