/*
 * vblasterlid.h
 *
 * Creative Labs VOIP Blaster codec interface
 *
 * Open H323 Library
 *
 * Copyright (c) 2001 Equivalence Pty. Ltd.
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
 * The Original Code is Open H323 Library.
 *
 * The Initial Developer of the Original Code is Equivalence Pty. Ltd.
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: vblasterlid.h,v $
 * Revision 1.8  2005/11/30 13:05:01  csoutheren
 * Changed tags for Doxygen
 *
 * Revision 1.7  2003/12/03 06:58:30  csoutheren
 * More vblaster implementation
 *
 * Revision 1.6  2003/11/10 12:37:46  csoutheren
 * Additional fixes for Fobbit Windows driver
 *
 * Revision 1.5  2002/09/16 01:14:15  robertj
 * Added #define so can select if #pragma interface/implementation is used on
 *   platform basis (eg MacOS) rather than compiler, thanks Robert Monaghan.
 *
 * Revision 1.4  2002/09/03 06:19:37  robertj
 * Normalised the multi-include header prevention ifdef/define symbol.
 *
 * Revision 1.3  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.2  2002/01/15 07:23:24  craigs
 * Added IsDevicePresent command
 *
 * Revision 1.1  2002/01/15 04:16:32  craigs
 * Initial version
 *
 *
 */

#ifndef __OPAL_VBLASTERLID_H
#define __OPAL_VBLASTERLID_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif


#define HAS_VBLASTER

#include "lid.h"
#include "h323caps.h"

#include <ptclib/delaychan.h>



///////////////////////////////////////////////////////////////////////////////

class VoipBlasterInterface : public PObject
{
  PCLASSINFO(VoipBlasterInterface, PObject)
  public:
    enum Command {
      Command_PHONE_OFF  = 0x01, // drop loop current
      Command_PHONE_ON   = 0x02, // used on startup
      Command_RING_ON    = 0x03, // start ringing
      Command_RING_OFF   = 0x04, // used on startup & to stop ringing
      Command_VOUT_START = 0x05, // start audio output
      Command_VOUT_STOP  = 0x06, // stop audio output
      Command_VINP_START = 0x07, // start audio input
      Command_VINP_STOP  = 0x08, // stop audio input
      Command_UNKNOWN_1  = 0x09, // Unknown (TESTSTART)
      Command_UNKNOWN_2  = 0x0a, // Unknown (TESTSTOP)
      Command_UNKNOWN_3  = 0x0b, // Unknown (SENDFAXTONE)
      Command_HS_OFFHOOK = 0x0c, // Go offhook for headset
      Command_HS_ONHOOK  = 0x0d, // Go onhook for headset
      Command_SETUP_MODE = 0x0e, // Unknown(goto setup mode)
      Command_VOUT_DONE  = 0x0f, // voice in/out off, report output drained
      Command_0x10       = 0x10, // Unknown (used in file output, seems ok without)
      Command_0x11       = 0x11, // Unknown (used in file output, seems ok without)
      Command_MUTE_ON    = 0x12, // Audio mute on
      Command_MUTE_OFF   = 0x13, // Audio mute off
      Command_VOL_0      = 0x34, // Set volume (min)
      Command_VOL_1      = 0x35, // Set volume
      Command_VOL_2      = 0x36, // Set volume
      Command_VOL_3      = 0x37, // Set volume (default)
      Command_VOL_4      = 0x38, // Set volume
      Command_VOL_5      = 0x39, // Set volume
      Command_VOL_6      = 0x3a, // Set volume (max)
    };

    enum Status {
      //Status_NONE        = 0x00, // No status
      Status_HOOK_OFF    = 0x01, // Offhook
      Status_HOOK_ON     = 0x02, // Onhook
      //Status_DEBUG       = 0x03, // Not used (DEBUG)
      //Status_RINGDETECT  = 0x04, // Not used (RINGDETECT)
      Status_RINGING_ON  = 0x05, // Ring started 
      Status_RINGING_OFF = 0x06, // Ring stopped
      Status_HEADSET_IN  = 0x08, // Headset plugged in
      Status_HEADSET_OUT = 0x09, // Headset unplugged
      Status_0x0a        = 0x0a, // Unknown (setup accepted?)
      Status_VOUT_DONE   = 0x0c, // Voice output done
      Status_Empty
    };

    VoipBlasterInterface();

    BOOL IsDevicePresent(PINDEX deviceIndex);

    BOOL OpenCommand(PINDEX deviceIndex);
    BOOL WriteCommand(Command cmd);
    Status ReadStatus(const PTimeInterval dur = 0);
    BOOL CloseCommand();

    BOOL OpenData();
    BOOL WriteData(const void * data, PINDEX len);
    int  ReadData (void * data,       PINDEX len, const PTimeInterval dur = 0);
    void Flush(const PTimeInterval wait = 500);
    BOOL CloseData();

    PDECLARE_NOTIFIER(PTimer, VoipBlasterInterface, CloseTimeout);

  protected:
    PINDEX deviceIndex;

// Linux specific defines are included here
#ifdef P_LINUX
#endif

// Windows specific defines are included here
#ifdef _WIN32
    enum Pipe {
      VoiceOutPipe = 0,
      VoiceInPipe  = 1,
      CommandPipe  = 2,
      StatusPipe   = 3,
      NumPipes
    };

  protected:
    int WritePipe(HANDLE fd, const void *bp, DWORD len);
    int ReadPipe (HANDLE fd, void *bp,       DWORD len, const PTimeInterval dur = 0);
    BOOL OpenVOIPPipe(Pipe pipeIndex);

    HANDLE pipes[4];
#endif
};

///////////////////////////////////////////////////////////////////////////////

/**This class describes the VoIPBlaster line interface device.
 */
class OpalVoipBlasterDevice : public OpalLineInterfaceDevice
{
  PCLASSINFO(OpalVoipBlasterDevice, OpalLineInterfaceDevice);

  public:

    enum { DTMFQueueSize = 10 };

    class ByteQueue : public PObject {
      PCLASSINFO(ByteQueue, PObject);
      public:
        ByteQueue(PINDEX size);
        int Dequeue();
        BOOL Enqueue(BYTE ch);

      protected:
        PBYTEArray queue;
        PINDEX qLen, qOut, qMax;
        PMutex mutex;
    };

    /**Create a new, closed, device for a VoipBlaster device.
      */
    OpalVoipBlasterDevice();

    /**Destroy line interface device.
       This calls Close() on the device.
      */
    ~OpalVoipBlasterDevice();

    /**Open the VoIPBlaster device.
      */
    virtual BOOL Open(
      const PString & device  ///<  Device identifier name.
    );

    /**Close the VoIPBlaster device.
      */
    virtual BOOL Close();

    /**Get the device name.
      */
    virtual PString GetName() const;

    /**Get the total number of lines supported by this device.
      */
    virtual unsigned GetLineCount()
      { return 1; }

    /**Get the type of the line.
      */
    virtual BOOL IsLineTerminal(
      unsigned /*line*/   ///<  Number of line
    ) { return TRUE; }


    /**Determine if a physical line is present on the logical line.
      */
    virtual BOOL IsLinePresent(
      unsigned /*line*/,      ///<  Number of line
      BOOL /*force*/ = FALSE  ///<  Force test, do not optimise
    )
      { return FALSE; }


    /**Determine if line is currently off hook.
       This returns TRUE if GetLineState() is a state that implies the line is
       off hook (eg OffHook or LineBusy).
      */
    virtual BOOL IsLineOffHook(
      unsigned line   ///<  Number of line
    );

    /**Set the state of the line.
       Note that not be possible on a given line.
      */
    virtual BOOL SetLineOffHook(
      unsigned line,        ///<  Number of line
      BOOL newState = TRUE  ///<  New state to set
    );


    /**Determine if line is ringing.
      */
    virtual BOOL IsLineRinging(
      unsigned line,          ///<  Number of line
      DWORD * cadence = NULL  ///<  Cadence of incoming ring
    );

    /**Begin ringing local phone set with specified cadence.
       If cadence is zero then stops ringing.
      */
    virtual BOOL RingLine(
      unsigned line,    ///<  Number of line
      DWORD cadence     ///<  Cadence bit map for ring pattern
    );


    /**Determine if line has been disconnected from a call.
      */
    virtual BOOL IsLineDisconnected(
      unsigned line,   ///<  Number of line
      BOOL checkForWink = TRUE
    );


    /**Directly connect the two lines.
      */
    BOOL SetLineToLineDirect(
      unsigned line1,   ///<  Number of first line
      unsigned line2,   ///<  Number of second line
      BOOL connect      ///<  Flag for connect/disconnect
    );

    /**Determine if the two lines are directly connected.
      */
    BOOL IsLineToLineDirect(
      unsigned line1,   ///<  Number of first line
      unsigned line2    ///<  Number of second line
    );


    /**Get the media formats this device is capable of using.
      */
    virtual OpalMediaFormat::List GetMediaFormats() const;

    /**Set the VoIPBlaster codec for reading.
      */
    virtual BOOL SetReadFormat(
      unsigned line,    ///<  Number of line
      const OpalMediaFormat & mediaFormat   ///<  Codec type
    );

    /**Set the VoIPBlaster codec for writing.
      */
    virtual BOOL SetWriteFormat(
      unsigned line,    ///<  Number of line
      const OpalMediaFormat & mediaFormat   ///<  Codec type
    );

    /**Get the media format (codec) for reading on the specified line.
      */
    virtual OpalMediaFormat GetReadFormat(
      unsigned line    ///<  Number of line
    );

    /**Get the media format (codec) for writing on the specified line.
      */
    virtual OpalMediaFormat GetWriteFormat(
      unsigned line    ///<  Number of line
    );

    /**Set the line codec for reading/writing raw PCM data.
       A descendent may use this to do anything special to the device before
       beginning special PCM output. For example disabling AEC and set
       volume levels to standard values. This can then be used for generating
       standard tones using PCM if the driver is not capable of generating or
       detecting them directly.

       The default behaviour simply does a SetReadCodec and SetWriteCodec for
       PCM data.
      */
    virtual BOOL SetRawCodec(
      unsigned line    ///<  Number of line
    );

    /**Stop the raw PCM mode codec.
      */
    virtual BOOL StopRawCodec(
      unsigned line   ///<  Number of line
    );

    /**Stop the read codec.
      */
    virtual BOOL StopReadCodec(
      unsigned line   ///<  Number of line
    );

    /**Stop the write codec.
      */
    virtual BOOL StopWriteCodec(
      unsigned line   ///<  Number of line
    );

    /**Get the read frame size in bytes.
       All calls to ReadFrame() will return this number of bytes.
      */
    virtual PINDEX GetReadFrameSize(
      unsigned line   ///<  Number of line
    );

    virtual BOOL SetReadFrameSize(unsigned, PINDEX);

    /**Get the write frame size in bytes.
       All calls to WriteFrame() must be this number of bytes.
      */
    virtual PINDEX GetWriteFrameSize(
      unsigned line   ///<  Number of line
    );

    virtual BOOL SetWriteFrameSize(unsigned, PINDEX);

    /**Low level read of a frame from the device.
     */
    virtual BOOL ReadFrame(
      unsigned line,    ///<  Number of line
      void * buf,       ///<  Pointer to a block of memory to receive data.
      PINDEX & count    ///<  Number of bytes read, <= GetReadFrameSize()
    );

    /**Low level write frame to the device.
     */
    virtual BOOL WriteFrame(
      unsigned line,    ///<  Number of line
      const void * buf, ///<  Pointer to a block of memory to write.
      PINDEX count,     ///<  Number of bytes to write, <= GetWriteFrameSize()
      PINDEX & written  ///<  Number of bytes written, <= GetWriteFrameSize()
    );

    /**Get average signal level in last frame.
      */
    virtual unsigned GetAverageSignalLevel(
      unsigned line,  ///<  Number of line
      BOOL playback   ///<  Get average playback or record level.
    );


    /**Enable audio for the line.
      */
    virtual BOOL EnableAudio(
      unsigned line,      ///<  Number of line
      BOOL enable = TRUE
    );


    /**Set volume level for recording.
       A value of 100 is the maximum volume possible for the hardware.
       A value of 0 is the minimum volume possible for the hardware.
      */
    virtual BOOL SetRecordVolume(
      unsigned line,    ///<  Number of line
      unsigned volume   ///<  Volume level from 0 to 100%
    );

    /**Set volume level for playing.
       A value of 100 is the maximum volume possible for the hardware.
       A value of 0 is the minimum volume possible for the hardware.
      */
    virtual BOOL SetPlayVolume(
      unsigned line,    ///<  Number of line
      unsigned volume   ///<  Volume level from 0 to 100%
    );

    /**Get volume level for recording.
       A value of 100 is the maximum volume possible for the hardware.
       A value of 0 is the minimum volume possible for the hardware.
      */
    virtual BOOL GetRecordVolume(
      unsigned line,      ///<  Number of line
      unsigned & volume   ///<  Volume level from 0 to 100%
    );

    /**Set volume level for playing.
       A value of 100 is the maximum volume possible for the hardware.
       A value of 0 is the minimum volume possible for the hardware.
      */
    virtual BOOL GetPlayVolume(
      unsigned line,      ///<  Number of line
      unsigned & volume   ///<  Volume level from 0 to 100%
    );


    /**Set acoustic echo cancellation.
      */
    AECLevels GetAEC(
      unsigned line    ///<  Number of line
    );

    /**Set acoustic echo cancellation.
      */
    BOOL SetAEC(
      unsigned line,    ///<  Number of line
      AECLevels level  ///<  AEC level
    );


    /**Get voice activity detection.
       Note, not all devices, or selected codecs, may support this function.
      */
    virtual BOOL GetVAD(
      unsigned line    ///<  Number of line
    );

    /**Set voice activity detection.
       Note, not all devices, or selected codecs, may support this function.
      */
    virtual BOOL SetVAD(
      unsigned line,    ///<  Number of line
      BOOL enable       ///<  Flag for enabling VAD
    );


    /**Get Caller ID from the last incoming ring.
       The idString parameter is either simply the "number" field of the caller
       ID data, or if full is TRUE, all of the fields in the caller ID data.

       The full data of the caller ID string consists of the number field, the
       time/date and the name field separated by tabs ('\t').
      */
    virtual BOOL GetCallerID(
      unsigned line,      ///<  Number of line
      PString & idString, ///<  ID string returned
      BOOL full = FALSE   ///<  Get full information in idString
    );

    /**Set Caller ID for use in next RingLine() call.
       The full data of the caller ID string consists of the number field, the
       time/date and the name field separated by tabs ('\t').

       If the date field is missing (two consecutive tabs) then the current
       time and date is used. Using an empty string will clear the caller ID
       so that no caller ID is sent on the next RingLine() call.
      */
    virtual BOOL SetCallerID(
      unsigned line,            ///<  Number of line
      const PString & idString  ///<  ID string to use
    );

    /**Send Caller ID during call
     */
    virtual BOOL SendCallerIDOnCallWaiting(
      unsigned line,            ///<  Number of line
      const PString & idString  ///<  ID string to use
    );

    /**Send a Visual Message Waiting Indicator
      */
    virtual BOOL SendVisualMessageWaitingIndicator(
      unsigned line,            ///<  Number of line
      BOOL on
    );



    /**Play a DTMF digit.
       Any characters that are not in the set 0-9, A-D, * or # will be ignored.
      */
    virtual BOOL PlayDTMF(
      unsigned line,            ///<  Number of line
      const char * digits,      ///<  DTMF digits to be played
      DWORD onTime = DefaultDTMFOnTime,  ///<  Number of milliseconds to play each DTMF digit
      DWORD offTime = DefaultDTMFOffTime ///<  Number of milliseconds between digits
    );

    /**Read a DTMF digit detected.
       This may be characters from the set 0-9, A-D, * or #. A null ('\0')
       character indicates that there are no tones in the queue.

      */
    virtual char ReadDTMF(
      unsigned line   ///<  Number of line
    );

    /**Get DTMF removal mode.
       When set in this mode the DTMF tones detected are removed from the
       encoded data stream as returned by ReadFrame().
      */
    virtual BOOL GetRemoveDTMF(
      unsigned line            ///<  Number of line
    );

    /**Set DTMF removal mode.
       When set in this mode the DTMF tones detected are removed from the
       encoded data stream as returned by ReadFrame().
      */
    virtual BOOL SetRemoveDTMF(
      unsigned line,            ///<  Number of line
      BOOL removeTones   ///<  Flag for removing DTMF tones.
    );


    /**See if a tone is detected.
      */
    virtual unsigned IsToneDetected(
      unsigned line   ///<  Number of line
    );

    /**Play a tone.
      */
    virtual BOOL PlayTone(
      unsigned line,          ///<  Number of line
      CallProgressTones tone  ///<  Tone to be played
    );

    /**Determine if a tone is still playing
      */
    virtual BOOL IsTonePlaying(
      unsigned line   ///<  Number of line
    );

    /**Stop playing a tone.
      */
    virtual BOOL StopTone(
      unsigned line   ///<  Number of line
    );

   /**Return TRUE if a hook flash has been detected
      */
    virtual BOOL HasHookFlash(unsigned line);

    /**Set the country code set for the device.
       This may change the line analogue coefficients, ring detect, call
       disconnect detect and call progress tones to fit the countries
       telephone network.
      */
    virtual BOOL SetCountryCode(
      T35CountryCodes country   ///<  COuntry code for device
    );


    /**Get the serial number for the VoIPBlaster card.
      */
    virtual DWORD GetSerialNumber();

    /**Get all the VoIPBlaster devices.
      */
    static PStringArray GetDeviceNames();

    /**
      * entry point for status handler thread
      */
    PDECLARE_NOTIFIER(PThread, OpalVoipBlasterDevice, StatusHandler);

  protected:
    void HandleStatus(int status);

    PThread * statusThread;
    BOOL statusRunning;
    BOOL hookState;
    BOOL headset;
    BOOL ringOn;
    BOOL firstTime;

    ByteQueue dtmfQueue;

    PAdaptiveDelay writeDelay;
    PAdaptiveDelay readDelay;

    PString   deviceName;
    PMutex    readMutex, writeMutex;
    BOOL      readStopped, writeStopped;
    PINDEX    readFrameSize, writeFrameSize;
    PINDEX    readCodecType, writeCodecType;
    BOOL      lastHookStatus;

    PMutex               vbMutex;
    VoipBlasterInterface vBlaster;
};


#endif // __OPAL_VBLASTERLID_H


/////////////////////////////////////////////////////////////////////////////
