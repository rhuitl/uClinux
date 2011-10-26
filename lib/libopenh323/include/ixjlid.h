/*
 * ixjlid.h
 *
 * QuickNet Internet Phone/Line JACK codec interface
 *
 * Open H323 Library
 *
 * Copyright (c) 1999-2000 Equivalence Pty. Ltd.
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
 * Portions of this code were written with the assisance of funding from
 * Quicknet Technologies, Inc. http://www.quicknet.net.
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: ixjlid.h,v $
 * Revision 1.69  2006/03/02 05:49:44  csoutheren
 * Fix for gcc 4.1.0
 *
 * Revision 1.68  2005/11/30 13:05:01  csoutheren
 * Changed tags for Doxygen
 *
 * Revision 1.67  2004/08/22 04:21:06  csoutheren
 * Added compiler.h for new glibc
 * Thanks to Klaus Kaempf
 *
 * Revision 1.66  2004/04/25 09:08:25  rjongbloed
 * Fixed being able to link of system does not have IxJ LID configured.
 *
 * Revision 1.65  2004/01/31 13:13:22  csoutheren
 * Fixed problem with HAS_IXJ being tested but not included
 *
 * Revision 1.64  2003/10/27 20:27:37  dereksmithies
 * Add log scale methods for audio.
 *
 * Revision 1.63  2003/04/29 08:27:47  robertj
 * Cleaned up documentation for new wink duration functions.
 *
 * Revision 1.62  2003/04/28 01:47:53  dereks
 * Add ability to set/get wink duration for ixj device.
 *
 * Revision 1.61  2002/11/06 04:03:38  dereks
 * Improve docs for  SetToneFilterParameters().
 *
 * Revision 1.60  2002/11/05 04:26:21  robertj
 * Imported RingLine() by array from OPAL.
 *
 * Revision 1.59  2002/09/16 01:14:15  robertj
 * Added #define so can select if #pragma interface/implementation is used on
 *   platform basis (eg MacOS) rather than compiler, thanks Robert Monaghan.
 *
 * Revision 1.58  2002/09/03 06:19:37  robertj
 * Normalised the multi-include header prevention ifdef/define symbol.
 *
 * Revision 1.57  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.56  2002/05/09 06:26:30  robertj
 * Added fuction to get the current audio enable state for line in device.
 * Changed IxJ EnableAudio() semantics so is exclusive, no direct switching
 *   from PSTN to POTS and vice versa without disabling the old one first.
 *
 * Revision 1.55  2001/09/24 12:31:35  robertj
 * Added backward compatibility with old drivers.
 *
 * Revision 1.54  2001/07/19 05:54:27  robertj
 * Updated interface to xJACK drivers to utilise cadence and filter functions
 *   for dial tone, busy tone and ringback tone detection.
 *
 * Revision 1.53  2001/05/21 06:36:46  craigs
 * Changed to allow optional wink detection for line disconnect
 *
 * Revision 1.52  2001/03/29 23:38:48  robertj
 * Added ability to get average signal level for both receive and transmit.
 *
 * Revision 1.51  2001/02/09 05:16:24  robertj
 * Added #pragma interface for GNU C++.
 *
 * Revision 1.50  2001/01/25 07:27:14  robertj
 * Major changes to add more flexible OpalMediaFormat class to normalise
 *   all information about media types, especially codecs.
 *
 * Revision 1.49  2001/01/24 05:34:49  robertj
 * Altered volume control range to be percentage, ie 100 is max volume.
 *
 * Revision 1.48  2000/12/19 06:38:57  robertj
 * Fixed missing virtual on IsTonePlaying() function.
 *
 * Revision 1.47  2000/12/11 01:47:28  robertj
 * Changed to use built PWLib class for overlapped I/O.
 *
 * Revision 1.46  2000/12/11 00:16:51  robertj
 * Removed unused filter/cadence function.
 *
 * Revision 1.45  2000/12/05 11:29:31  craigs
 * Fixed problem with DTMF signal by adding queue for DTMF digits
 *
 * Revision 1.44  2000/12/04 23:30:02  craigs
 * Added better initialisation of Quicknet devices
 *
 * Revision 1.43  2000/11/30 21:28:47  eokerson
 * Fixed DTMF signal handling to stop polling ixj driver.
 *
 * Revision 1.42  2000/11/30 08:48:35  robertj
 * Added functions to enable/disable Voice Activity Detection in LID's
 *
 * Revision 1.41  2000/11/27 10:30:01  craigs
 * Added SetRawCodec function
 *
 * Revision 1.40  2000/11/27 00:12:17  robertj
 * Added WIN32 version of hook flash detection function.
 *
 * Revision 1.39  2000/11/26 23:12:18  craigs
 * Added hook flash detection API
 *
 * Revision 1.38  2000/11/24 11:18:36  robertj
 * Don't need special raw modes for Linux drivers ... yet.
 *
 * Revision 1.37  2000/11/24 10:50:13  robertj
 * Added a raw PCM dta mode for generating/detecting standard tones.
 * Modified the ReadFrame/WriteFrame functions to allow for variable length codecs.
 * Fixed hook state debouncing.
 * Added codec to explicitly set LineJACK mixer settings to avoid funny modes
 *    the driver/hardware gets into sometimes.
 *
 * Revision 1.36  2000/11/20 03:15:13  craigs
 * Changed tone detection API slightly to allow detection of multiple
 * simultaneous tones
 * Added fax CNG tone to tone list
 *
 * Revision 1.35  2000/11/12 22:34:32  craigs
 * Changed Linux driver interface code to use signals
 *
 * Revision 1.34  2000/11/06 06:33:20  robertj
 * Changed hook state debounce so does not block for 200ms.
 *
 * Revision 1.33  2000/11/03 06:22:48  robertj
 * Added flag to IsLinePresent() to force slow test, guarenteeing correct value.
 *
 * Revision 1.32  2000/10/23 05:39:07  craigs
 * Added access to exception detection on Unix
 * Fixed problem with detecting available devices when
 * devices with lower ordinals were used
 *
 * Revision 1.31  2000/10/19 04:12:13  robertj
 * Added enum for xJACK card types.
 *
 * Revision 1.30  2000/10/19 04:00:35  robertj
 * Added functions to get xJACK card type and serial number.
 *
 * Revision 1.29  2000/10/13 02:21:40  robertj
 * Changed volume control code to set more mixer values on LineJACK.
 *
 * Revision 1.28  2000/09/25 23:59:42  craigs
 * Finally got G.728 working on boards which use the 8021
 * Added better handling for wink exceptions
 *
 * Revision 1.27  2000/09/22 01:35:03  robertj
 * Added support for handling LID's that only do symmetric codecs.
 *
 * Revision 1.26  2000/09/13 09:26:28  rogerh
 * Add location of FreeBSD header files
 *
 * Revision 1.25  2000/09/08 06:43:42  craigs
 * Added additional ioctl debugging
 * Added attempt to reduce ioctl count for hookstate monitoring
 *
 * Revision 1.24  2000/08/31 13:14:39  craigs
 * Added functions to LID
 * More bulletproofing to Linux driver
 *
 * Revision 1.23  2000/07/28 06:29:20  robertj
 * Fixed AEC under Win32 so can be changed from other processes.
 *
 * Revision 1.22  2000/06/22 02:47:12  craigs
 * Improved PSTN ring detection
 *
 * Revision 1.21  2000/06/17 09:34:45  robertj
 * Put back variables mistakenly thought to be Linux specific.
 *
 * Revision 1.20  2000/06/17 04:11:13  craigs
 * Fixed problem with potential codec startup problem in Linux IXJ driver
 * Moved Linux specific variables to Linux specific section
 *
 * Revision 1.19  2000/05/24 06:42:18  craigs
 * Added calls to get volume settings
 *
 * Revision 1.18  2000/05/02 04:32:24  robertj
 * Fixed copyright notice comment.
 *
 * Revision 1.17  2000/04/13 23:09:38  craigs
 * Fixed problem with callerId on some systems
 *
 * Revision 1.16  2000/04/06 20:36:25  robertj
 * Fixed some LineJACK compatbility problems (eg DTMF detect stopping).
 *
 * Revision 1.15  2000/04/06 19:37:50  craigs
 * Normalised bask to HAS_IXJ
 *
 * Revision 1.14  2000/04/06 19:29:04  craigs
 * Removed all vestiges of the old IXJ driver
 *
 * Revision 1.13  2000/04/06 17:49:40  craigs
 * Removed LINUX_TELEPHONY. Again.
 *
 * Revision 1.12  2000/04/05 18:04:12  robertj
 * Changed caller ID code for better portability.
 *
 * Revision 1.11  2000/04/05 16:28:05  craigs
 * Added caller ID function
 *
 * Revision 1.10  2000/03/29 20:46:47  robertj
 * Added function on LID to get available codecs.
 *
 * Revision 1.9  2000/03/28 03:47:12  craigs
 * Added stuff to stop tone playing from going wrong
 *
 * Revision 1.8  2000/03/22 17:18:48  robertj
 * Changed default DTMF tone string times.
 *
 * Revision 1.7  2000/03/17 20:58:51  robertj
 * Fixed line count to be xJACK card dependent.
 *
 * Revision 1.6  2000/03/14 11:20:49  rogerh
 * Compile the ixj code on FreeBSD. This is needed for openphone support.
 *
 * Revision 1.5  2000/02/22 09:44:33  robertj
 * Fixed compatibility with Linux systems not yet with the Linux Telephony code.
 *
 * Revision 1.4  2000/01/07 10:01:26  robertj
 * GCC/Linux compatibility
 *
 * Revision 1.3  2000/01/07 08:28:09  robertj
 * Additions and changes to line interface device base class.
 *
 * Revision 1.2  1999/12/24 00:28:03  robertj
 * Changes to IXJ interface to follow LID abstraction
 *
 * Revision 1.1  1999/12/23 23:02:35  robertj
 * File reorganision for separating RTP from H.323 and creation of LID for VPB support.
 *
 */

#ifndef __OPAL_IXJLID_H
#define __OPAL_IXJLID_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#include "openh323buildopts.h"

#ifdef HAS_IXJ

#include "lid.h"
#include "h323caps.h"


#ifdef P_LINUX
#include <linux/telephony.h>
#include <linux/compiler.h>
#include <linux/ixjuser.h>
#endif

#ifdef P_FREEBSD
#include <sys/telephony.h>
#include <sys/ixjuser.h>
#endif



///////////////////////////////////////////////////////////////////////////////

/**This class describes the xJack line interface device.
 */
class OpalIxJDevice : public OpalLineInterfaceDevice
{
  PCLASSINFO(OpalIxJDevice, OpalLineInterfaceDevice);

  enum { MaxIxjDevices = 10 };

  public:
    /**Create a new, closed, device for a xJack card.
      */
    OpalIxJDevice();

    /**Destroy line interface device.
       This calls Close() on the device.
      */
    ~OpalIxJDevice() { Close(); }

    /**Open the xJack device.
      */
    virtual BOOL Open(
      const PString & device  ///<  Device identifier name.
    );

    /**Close the xJack device.
      */
    virtual BOOL Close();

    /**Get the device name.
      */
    virtual PString GetName() const;


    enum {
      POTSLine,
      PSTNLine,
      NumLines
    };

    /**Get the total number of lines supported by this device.
      */
    virtual unsigned GetLineCount();


    /**Get the type of the line.
      */
    virtual BOOL IsLineTerminal(
      unsigned line   ///<  Number of line
    ) { return line == POTSLine; }


    /**Determine if a physical line is present on the logical line.
      */
    virtual BOOL IsLinePresent(
      unsigned line,      ///<  Number of line
      BOOL force = FALSE  ///<  Force test, do not optimise
    );


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

    /**Begin ringing local phone set with specified cadence.
       If nCadence is zero then stops ringing.

       Note that not be possible on a given line, for example on a PSTN line
       the ring state is determined by external hardware and cannot be
       changed by the software.

       Also note that the cadence may be ignored by particular hardware driver
       so that only the zero or non-zero values are significant.

       The ring pattern is an array of millisecond times for on and off parts
       of the cadence. Thus the Australian ring cadence would be represented
       by the array   unsigned AusRing[] = { 400, 200, 400, 2000 }
      */
    virtual BOOL RingLine(
      unsigned line,     ///<  Number of line
      PINDEX nCadence,   ///<  Number of entries in cadence array
      unsigned * pattern ///<  Ring pattern times
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

    /**Set the xJack codec for reading.
      */
    virtual BOOL SetReadFormat(
      unsigned line,    ///<  Number of line
      const OpalMediaFormat & mediaFormat   ///<  Codec type
    );

    /**Set the xJack codec for writing.
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

    /**Determine if audio for the line is enabled.
      */
    virtual BOOL IsAudioEnabled(
      unsigned line      ///<  Number of line
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

    /**Get acoustic echo cancellation.
      */
    AECLevels GetAEC(
      unsigned line    ///<  Number of line
    );

    /**Set acoustic echo cancellation.
      */
    BOOL SetAEC(
      unsigned line,    ///<  Number of line
      AECLevels level   ///<  AEC level
    );

    /**Get wink detect minimum duration.
       This is the signal used by telcos to end PSTN call.
      */
    unsigned GetWinkDuration(
      unsigned line    ///<  Number of line
    );

    /**Set wink detect minimum duration.
       This is the signal used by telcos to end PSTN call.
      */
    BOOL SetWinkDuration(
      unsigned line,        ///<  Number of line
      unsigned winkDuration ///<  New minimum duration
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

    /**Set a tones filter parameters.

       The times are in centi-seconds. 
       Thus, to have a 1 second delay, 100 is required.
      */
    virtual BOOL SetToneFilterParameters(
      unsigned line,            ///<  Number of line
      CallProgressTones tone,   ///<  Tone filter to change
      unsigned lowFrequency,    ///<  Low frequency
      unsigned highFrequency,   ///<  High frequency
      PINDEX numCadences,       ///<  Number of cadence times
      const unsigned * onTimes, ///<  Cadence ON times
      const unsigned * offTimes ///<  Cadence OFF times
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


    /**Get the serial number for the xJACK card.
      */
    virtual DWORD GetSerialNumber();

    enum CardTypes {
      PhoneJACK = 1,
      LineJACK = 3,
      PhoneJACK_Lite,
      PhoneJACK_PCI,
      PhoneCARD,
      PhoneJACK_PCI_TJ
    };

    /**Get the serial number for the xJACK card.
      */
    DWORD GetCardType() const { return dwCardType; }


    /**Get all the xJack devices.
      */
    static PStringArray GetDeviceNames();


  protected:

    PINDEX    LogScaleVolume(unsigned line, PINDEX volume, BOOL isPlay);

    PString   deviceName;
    DWORD     dwCardType;
    PMutex    readMutex, writeMutex;
    BOOL      readStopped, writeStopped;
    PINDEX    readFrameSize, writeFrameSize;
    PINDEX    readCodecType, writeCodecType;
    BOOL      lastHookState, currentHookState;
    PTimer    hookTimeout;
    BOOL      inRawMode;
    unsigned  enabledAudioLine;
    BOOL      exclusiveAudioMode;

#if defined(WIN32)
    BOOL InternalSetVolume(BOOL record, unsigned id, int volume, int mute);
    BOOL InternalPlayTone(unsigned line,
                          DWORD toneIndex,
                          DWORD onTime, DWORD offTime,
                          BOOL synchronous);
    BOOL IoControl(DWORD dwIoControlCode,
                   DWORD inParam = 0,
                   DWORD * outParam = NULL);
    BOOL IoControl(DWORD dwIoControlCode,
                   LPVOID lpInBuffer,
                   DWORD nInBufferSize,
                   LPVOID lpOutBuffer,
                   DWORD nOutBufferSize,
                   LPDWORD lpdwBytesReturned,
                   PWin32Overlapped * overlap = NULL);

    HANDLE        hDriver;
    DWORD         driverVersion;
    PTimer        ringTimeout;
    DWORD         lastDTMFDigit;
    DWORD         lastFlashState;
    PTimeInterval toneSendCompletionTime;
    BOOL          vadEnabled;
    HANDLE        hReadEvent, hWriteEvent;

#elif defined(HAS_IXJ)

  public:
    class ExceptionInfo {
      public:
        int fd;

        BOOL hasRing;
        BOOL hookState;
        BOOL hasWink;
        BOOL hasFlash;
        char dtmf[16];
        int dtmfIn;
        int dtmfOut;
#ifdef IXJCTL_VMWI
        BOOL hasCid;
        PHONE_CID cid;
#endif
        BOOL filter[4];
        BOOL cadence[4];
        telephony_exception data;
        timeval lastHookChange;
    };

    static void SignalHandler(int sig);
    ExceptionInfo * GetException();
    int GetOSHandle() { return os_handle; }

  protected:
    BOOL ConvertOSError(int err);

    static ExceptionInfo exceptionInfo[MaxIxjDevices];
    static PMutex        exceptionMutex;
    static BOOL          exceptionInit;

    AECLevels aecLevel;
    BOOL removeDTMF;
    PMutex toneMutex;
    BOOL tonePlaying;
    PTimer lastRingTime;
    BOOL pstnIsOffHook;
    BOOL gotWink;
    int  userPlayVol, userRecVol;

    int  savedPlayVol, savedRecVol;
    AECLevels savedAEC;

#ifdef IXJCTL_VMWI
    PHONE_CID callerIdInfo;
#endif

#endif
};


#endif // HAS_IXJ

#endif // __OPAL_IXJLID_H


/////////////////////////////////////////////////////////////////////////////
