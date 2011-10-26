/*
 * ixjwin32.cxx
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
 * $Log: ixjwin32.cxx,v $
 * Revision 1.117  2005/08/04 19:38:51  csoutheren
 * Applied patch #1240871
 * Fixed problem with disabling IXJ code
 * Thanks to Borko Jandras
 *
 * Revision 1.116  2005/06/07 07:59:11  csoutheren
 * Applied patch 1176459 for PocketPC. Thanks to Matthias Weber
 *
 * Revision 1.115  2004/04/09 12:56:52  rjongbloed
 * Fixed automatic loading of winmm.lib if this module included.
 *
 * Revision 1.114  2003/04/29 08:32:59  robertj
 * Added new wink functions for Windows IxJ lid.
 *
 * Revision 1.113  2002/11/05 04:33:21  robertj
 * Changed IsLineDisconnected() to work with POTSLine
 *
 * Revision 1.112  2002/11/05 04:27:58  robertj
 * Imported RingLine() by array from OPAL.
 *
 * Revision 1.111  2002/10/30 05:54:17  craigs
 * Fixed compatibilty problems with G.723.1 6k3 and 5k3
 *
 * Revision 1.110  2002/06/25 08:30:12  robertj
 * Changes to differentiate between stright G.723.1 and G.723.1 Annex A using
 *   the OLC dataType silenceSuppression field so does not send SID frames
 *   to receiver codecs that do not understand them.
 *
 * Revision 1.109  2002/05/09 06:26:34  robertj
 * Added fuction to get the current audio enable state for line in device.
 * Changed IxJ EnableAudio() semantics so is exclusive, no direct switching
 *   from PSTN to POTS and vice versa without disabling the old one first.
 *
 * Revision 1.108  2002/03/21 02:37:33  robertj
 * Fixed G.723.1 5.3k mode so receiver (playback) still accepts 6.3k data.
 *
 * Revision 1.107  2002/02/08 14:41:49  craigs
 * Changed codec table to use mediatream #defines. Thanks to Roger Hardiman
 *
 * Revision 1.106  2001/12/11 04:27:28  craigs
 * Added support for 5.3kbps G723.1
 *
 * Revision 1.105  2001/12/03 00:40:43  robertj
 * Fixed problem with false off hook detect with LineJACK and no PSTN active.
 *
 * Revision 1.104  2001/10/11 00:48:08  robertj
 * Changed so if stopping read/write also stops fax and vice versa.
 *
 * Revision 1.103  2001/09/25 01:12:06  robertj
 * Changed check to v 5.5.141
 *
 * Revision 1.102  2001/09/24 12:31:35  robertj
 * Added backward compatibility with old drivers.
 *
 * Revision 1.101  2001/09/10 08:22:16  robertj
 * Fixed minor problems with error codes.
 *
 * Revision 1.100  2001/07/24 02:29:56  robertj
 * Added setting of xJack filter coefficients for some frequencies,
 *    values taken from open source Linux driver.
 *
 * Revision 1.99  2001/07/19 05:54:30  robertj
 * Updated interface to xJACK drivers to utilise cadence and filter functions
 *   for dial tone, busy tone and ringback tone detection.
 *
 * Revision 1.98  2001/07/06 03:44:35  robertj
 * Oops, the WAVE output should ALWAYS be unmuted!
 *
 * Revision 1.97  2001/07/06 00:45:15  robertj
 * Fixed accidentlaly unmuting microphone on audio output for LineJACKs.
 *
 * Revision 1.96  2001/06/12 00:12:23  craigs
 * No longer looks for dialtone for end of call
 *
 * Revision 1.95  2001/05/30 04:06:26  robertj
 * Fixed setting of LineJACK mixer mutes to AFTER setting of analague source
 *   as each source has different mixer settings in driver.
 * Change start of codec (SetXXXFormat()) to explicitly stop codec.
 *
 * Revision 1.94  2001/05/25 02:19:53  robertj
 * Fixed problem with codec data reblocking code not being reset when
 *   code is stopped and restarted, thanks Artis Kugevics
 *
 * Revision 1.93  2001/05/21 06:37:06  craigs
 * Changed to allow optional wink detection for line disconnect
 *
 * Revision 1.92  2001/05/11 04:43:43  robertj
 * Added variable names for standard PCM-16 media format name.
 *
 * Revision 1.91  2001/05/10 02:07:11  robertj
 * Fixed possibility of output on POTS/PSTN being muted accidentally and
 *   thus not having any audio. Explicitly unmutes it on selection.
 *
 * Revision 1.90  2001/04/20 02:27:29  robertj
 * Added extra mutex in SetReadFormat() for if it ever gets called without
 *     a StopCodec() beforehand.
 *
 * Revision 1.89  2001/04/18 02:31:58  craigs
 * Fixed problem with illegal date in caller ID causing assert
 *
 * Revision 1.88  2001/04/09 08:46:16  robertj
 * Added implementations to set mode for removing DTMF from media.
 *
 * Revision 1.87  2001/03/31 02:55:55  robertj
 * Removed some interlocks on functions that are no longer required in current drivers.
 *
 * Revision 1.86  2001/03/30 05:46:09  robertj
 * Added trace output of driver version number.
 * Added check for PSTN line disconnect to include looking for tones.
 *
 * Revision 1.85  2001/03/29 23:40:46  robertj
 * Added ability to get average signal level for both receive and transmit.
 * Changed G.729A silence frames to be CNG frames to stop clicking sound.
 *
 * Revision 1.84  2001/03/24 00:52:34  robertj
 * Fixed incorrect conditional on error trace for G.729B packet in G.729A mode.
 *
 * Revision 1.83  2001/03/23 05:38:09  robertj
 * Added PTRACE_IF to output trace if a conditional is TRUE.
 * Indicate if get sent a G.729B packet when in G.729A mode.
 *
 * Revision 1.82  2001/03/22 06:18:49  robertj
 * Fixed very subtle problem with Quicknet cards under NT/2K, caused occassional
 *   blip in continuous audio due to the resolution of internal timers.
 *
 * Revision 1.81  2001/02/21 08:09:15  robertj
 * Added more tones for characters 'e' through 'o'.
 *
 * Revision 1.80  2001/02/16 08:18:17  robertj
 * Fixed IXJ interface to compensate for driver bug.
 *
 * Revision 1.79  2001/02/15 05:15:34  robertj
 * Compensated for driver failing to return serial number on Win98.
 *
 * Revision 1.78  2001/02/07 05:02:58  robertj
 * Temporary removal of code due to broken driver.
 *
 * Revision 1.77  2001/01/25 07:27:16  robertj
 * Major changes to add more flexible OpalMediaFormat class to normalise
 *   all information about media types, especially codecs.
 *
 * Revision 1.76  2001/01/24 05:34:49  robertj
 * Altered volume control range to be percentage, ie 100 is max volume.
 *
 * Revision 1.75  2001/01/11 05:39:44  robertj
 * Fixed usage of G.723.1 CNG 1 byte frames.
 *
 * Revision 1.74  2000/12/18 21:56:13  robertj
 * Fixed saving of POTS/PSTN link state when doing PSTN line test.
 * Changed caller ID code to allow for single record protocol.
 *
 * Revision 1.73  2000/12/17 23:08:01  robertj
 * Changed driver close so goes into POTS/PSTN pass through mode.
 *
 * Revision 1.72  2000/12/12 07:51:36  robertj
 * Changed name to include word Internet as in Linux driver.
 *
 * Revision 1.71  2000/12/11 01:47:14  robertj
 * Changed to use built PWLib class for overlapped I/O.
 *
 * Revision 1.70  2000/11/30 08:48:36  robertj
 * Added functions to enable/disable Voice Activity Detection in LID's
 *
 * Revision 1.69  2000/11/30 05:59:57  robertj
 * Changed raw mode transfer block size to 30ms blocks.
 * Removed test of raw mode read/write as driver returns incorrect value.
 * Added PTRACE of error code from driver when error occurs.
 * Fixed bug in raw mode write, count of bytes too large if second write in loop.
 *
 * Revision 1.68  2000/11/28 01:59:53  robertj
 * Removed usage of deprecated volume setting calls.
 *
 * Revision 1.67  2000/11/27 00:12:18  robertj
 * Added WIN32 version of hook flash detection function.
 *
 * Revision 1.66  2000/11/24 10:58:47  robertj
 * Added a raw PCM dta mode for generating/detecting standard tones.
 * Modified the ReadFrame/WriteFrame functions to allow for variable length codecs.
 * Fixed hook state debouncing.
 * Added codec to explicitly set LineJACK mixer settings to avoid funny modes
 *    the driver/hardware gets into sometimes.
 * Changed tone detection API slightly to allow detection of multiple
 *    simultaneous tones
 *
 * Revision 1.65  2000/11/06 06:33:26  robertj
 * Changed hook state debounce so does not block for 200ms.
 *
 * Revision 1.64  2000/11/03 06:25:37  robertj
 * Added flag to IsLinePresent() to force slow test, guarenteeing correct value.
 *
 * Revision 1.63  2000/10/26 12:24:56  robertj
 * Added configurable G.729 codec usage, based on separate license.
 *
 * Revision 1.62  2000/10/19 04:04:04  robertj
 * Added functions to get xJACK card type and serial number.
 *
 * Revision 1.61  2000/10/13 02:21:28  robertj
 * Changed volume control code to set more mixer values on LineJACK.
 *
 * Revision 1.60  2000/09/26 02:17:35  robertj
 * Fixed MSVC warning
 *
 * Revision 1.59  2000/09/26 01:48:36  robertj
 * Removed now redundent AEC resetting when starting read/write codec.
 *
 * Revision 1.58  2000/09/23 06:55:24  robertj
 * Put code back so gets driver default frame size instead of trying to set it. Caused lockups.
 *
 * Revision 1.57  2000/09/22 01:35:51  robertj
 * Added support for handling LID's that only do symmetric codecs.
 *
 * Revision 1.56  2000/09/15 23:01:50  robertj
 * Fixed choppy audio in som cases with PCM, explicitly set frame size now.
 *
 * Revision 1.55  2000/09/05 22:07:50  robertj
 * Removed deprecated IOCTL_Idle_Idle.
 *
 * Revision 1.54  2000/09/04 05:45:03  robertj
 * Added VMWI support and country codes to IXJ driver interface.
 *
 * Revision 1.53  2000/09/01 01:25:05  robertj
 * Fixed incorrect class names and began country code setting of driver.
 *
 * Revision 1.52  2000/08/31 13:14:40  craigs
 * Added functions to LID
 * More bulletproofing to Linux driver
 *
 * Revision 1.51  2000/08/30 22:57:46  robertj
 * Removed call to CancelIO, does not exist in Win95!
 *
 * Revision 1.50  2000/08/21 02:49:14  robertj
 * Added timeout for driver read/write, should never block for long.
 *
 * Revision 1.49  2000/08/01 03:24:49  robertj
 * Changed enumeration of Quicknet devices to use new technique for future Win2k drives.
 *
 * Revision 1.48  2000/07/28 06:29:20  robertj
 * Fixed AEC under Win32 so can be changed from other processes.
 *
 * Revision 1.47  2000/07/25 02:07:34  robertj
 * Reduced max range of device numbers as can get some low serial numbers.
 *
 * Revision 1.46  2000/07/14 14:12:06  robertj
 * Added turning off of VAD which results in 1 byte G.723.1 frames that not
 *    everyone supports yet.
 *
 * Revision 1.45  2000/07/12 10:25:07  robertj
 * Added PhoneCARD support on Win9x systems.
 *
 * Revision 1.44  2000/06/20 12:51:23  robertj
 * Changed IXJ driver open so does not change selected line to PSTN.
 *
 * Revision 1.43  2000/06/20 02:22:41  robertj
 * Fixed NT version so can still use serial number to open device.
 *
 * Revision 1.42  2000/06/19 00:31:30  robertj
 * Changed NT device name to be a bit more user friendly.
 *
 * Revision 1.41  2000/06/08 02:33:25  robertj
 * Fixed detection of correct xJack card type under NT.
 * Added ability to use just "0" or "1" instead of "\\.\QTJackDevice0" as device name.
 *
 * Revision 1.40  2000/05/25 02:23:25  robertj
 * Added calls to get volume settings
 *
 * Revision 1.39  2000/05/15 08:38:59  robertj
 * Changed LineJACK PSTN check so is initiated only if state unknown.
 *
 * Revision 1.38  2000/05/02 04:32:27  robertj
 * Fixed copyright notice comment.
 *
 * Revision 1.37  2000/04/30 04:00:33  robertj
 * Changed determination of frame size to use driver ioctl for PCM, uLAw and ALaw.
 *
 * Revision 1.36  2000/04/28 07:00:26  robertj
 * Fixed race condition causing RTP send thread to randomly shut down.
 *
 * Revision 1.35  2000/04/19 01:57:39  robertj
 * Added mixer code to get volume control support on LineJACK;s.
 * Attempt to prevent getting very occassional ReadFrame() failure causing tx channel stop.
 *
 * Revision 1.34  2000/04/12 23:56:37  robertj
 * Fixed detection of PCI PhoneJACK on NT.
 *
 * Revision 1.33  2000/04/06 20:36:25  robertj
 * Fixed some LineJACK compatbility problems (eg DTMF detect stopping).
 *
 * Revision 1.32  2000/04/05 20:55:41  robertj
 * Added caller ID send, and fixed receive for multiple fields.
 *
 * Revision 1.31  2000/04/05 18:04:12  robertj
 * Changed caller ID code for better portability.
 *
 * Revision 1.30  2000/03/30 01:55:13  robertj
 * Added function so silence detection can work on xJack internetl codecs.
 * Fixed length of G.728 codec frames
 *
 * Revision 1.29  2000/03/29 20:59:52  robertj
 * Added function on LID to get available codecs.
 * Improved consistency in "device name".
 * Fixed codec table for G.729 codec
 * Fixed lockup bug with tone/codec interaction.
 *
 * Revision 1.28  2000/03/23 02:48:49  robertj
 * Added calling tone detection code.
 *
 * Revision 1.27  2000/03/17 20:59:42  robertj
 * Fixed line count to be xJACK card dependent.
 * Added support for more xJACK card types.
 *
 * Revision 1.26  2000/02/24 00:35:22  robertj
 * Fixed problem with unresolved SetRemoveDTMF function when not using linux telephony.
 *
 * Revision 1.25  2000/02/16 04:04:37  robertj
 * Fixed bug where IXJ POTS handset never returned off hook.
 *
 * Revision 1.24  2000/01/07 08:28:09  robertj
 * Additions and changes to line interface device base class.
 *
 * Revision 1.23  1999/12/30 09:16:41  robertj
 * Fixed initialisation of driver handle, prevent crash in Close().
 *
 * Revision 1.22  1999/12/23 23:02:36  robertj
 * File reorganision for separating RTP from H.323 and creation of LID for VPB support.
 *
 * Revision 1.21  1999/11/29 04:50:11  robertj
 * Added adaptive threshold calculation to silence detection.
 *
 * Revision 1.20  1999/11/20 04:38:03  robertj
 * Removed potential driver lockups by doing overlapped I/O only on read/write ioctls.
 *
 * Revision 1.19  1999/11/19 09:17:15  robertj
 * Fixed problems with aycnhronous shut down of logical channels.
 *
 * Revision 1.18  1999/11/16 12:43:02  robertj
 * Dixed missing initialise of AEC variable.
 *
 * Revision 1.17  1999/11/16 11:32:06  robertj
 * Added some calling tones.
 *
 * Revision 1.16  1999/11/12 02:25:01  robertj
 * More NT support.
 *
 * Revision 1.15  1999/11/11 23:15:31  robertj
 * Fixed bug where closed driver was not flagged as closed.
 *
 * Revision 1.14  1999/11/11 01:16:57  robertj
 * Added NT support, debounce of phone hook state and wait for line test completion.
 *
 * Revision 1.13  1999/11/06 05:36:19  robertj
 * Fixed problem with read/write locking up when stopping codec.
 *
 * Revision 1.12  1999/11/06 03:32:27  robertj
 * Added volume control functions for record/playback.
 *
 * Revision 1.11  1999/11/05 12:53:40  robertj
 * Fixed warnings on notrace version.
 *
 * Revision 1.10  1999/11/05 10:51:18  robertj
 * Fixed problem with new ixj channel doing incorrect double initialise
 *
 * Revision 1.9  1999/11/05 08:54:41  robertj
 * Rewrite of ixj interface code to fix support for arbitrary codecs.
 *
 * Revision 1.8  1999/11/02 00:24:29  robertj
 * Added GetCallerID() function and implemented some LineJACK code.
 *
 * Revision 1.7  1999/11/01 01:20:26  robertj
 * Added flunction to enabled/disable DTM detection
 *
 * Revision 1.6  1999/11/01 00:47:14  robertj
 * Fixed problems with stopping codecs
 *
 * Revision 1.5  1999/10/30 12:43:25  robertj
 * Fixed "lock up" problem, DTMF problem and added function to get line status.
 *
 * Revision 1.4  1999/10/28 12:21:34  robertj
 * Added AEC support and speakerphone switching button.
 *
 * Revision 1.3  1999/10/27 06:30:31  robertj
 * Added CancelIO command when closing channel.
 *
 * Revision 1.2  1999/10/24 14:51:41  robertj
 * Removed EnableDetectDTMF() as unix ioctl does not exist.
 *
 * Revision 1.1  1999/10/24 12:59:41  robertj
 * Added platform independent support for Quicknet xJACK cards.
 *
 */

#include <ptlib.h>
#include "ixjlid.h"

#include <QTIoctl.h>
#include <ixjDefs.h>

#ifdef HAS_IXJ

#ifndef _WIN32_WINCE
#pragma comment(lib, "winmm.lib")
#endif

#define NEW_DRIVER_VERSION ((5<<24)|(5<<16)|141)

#define new PNEW


static enum {
  IsWindows9x,
  IsWindowsNT,
  IsWindows2k
} GetOperatingSystem()
{
  static OSVERSIONINFO version;
  if (version.dwOSVersionInfoSize == 0) {
    version.dwOSVersionInfoSize = sizeof(version);
    GetVersionEx(&version);
  }
  if (version.dwPlatformId != VER_PLATFORM_WIN32_NT)
    return IsWindows9x;
  if (version.dwMajorVersion < 5)
    return IsWindowsNT;
  return IsWindows2k;
}

#define IsLineJACK() (dwCardType == 3)


/////////////////////////////////////////////////////////////////////////////

OpalIxJDevice::OpalIxJDevice()
{
  hDriver = INVALID_HANDLE_VALUE;
  driverVersion = 0;
  readStopped = writeStopped = TRUE;
  readFrameSize = writeFrameSize = 480;  // 30 milliseconds of 16 bit PCM data
  readCodecType = writeCodecType = P_MAX_INDEX;
  currentHookState = lastHookState = FALSE;
  inRawMode = FALSE;
  enabledAudioLine = UINT_MAX;
  exclusiveAudioMode = TRUE;
  lastDTMFDigit = 0;
  hReadEvent = hWriteEvent = NULL;
}


BOOL OpalIxJDevice::Open(const PString & device)
{
  Close();

  PTRACE(3, "xJack\tOpening IxJ device \"" << device << '"');

  DWORD dwDeviceId = device.AsUnsigned(16);

  PString devicePath;
  const char * DevicePathPrefix = "\\\\.\\QTJACKDevice";

  switch (GetOperatingSystem()) {
    case IsWindows2k :
      DevicePathPrefix = "\\\\.\\QTIWDMDevice";
      // Flow into NT case

    case IsWindowsNT :
      if (dwDeviceId < 100) {
        devicePath = device.Left(device.Find(' '));
        if (strspn(devicePath, "0123456789") == strlen(devicePath))
          devicePath = DevicePathPrefix + devicePath;
      }
      else {
        PStringArray allDevices = GetDeviceNames();
        for (PINDEX dev = 0; dev < allDevices.GetSize(); dev++) {
          PString thisDevice = allDevices[dev];
          if (thisDevice.Find(device) != P_MAX_INDEX) {
            devicePath = thisDevice.Left(thisDevice.Find(' '));
            break;
          }
        }
      }
      timeBeginPeriod(2);
      break;

    case IsWindows9x :
      devicePath = "\\\\.\\Qtipj.vxd";
  }

  hDriver = CreateFile(devicePath,
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                       NULL);
  if (hDriver == INVALID_HANDLE_VALUE) {
    osError = ::GetLastError()|PWIN32ErrorFlag;
    return FALSE;
  }

  if (GetOperatingSystem() == IsWindows9x) {
    DWORD dwResult = 0;
    if (!IoControl(IOCTL_Device_Open, dwDeviceId, &dwResult) || dwResult == 0) {
      CloseHandle(hDriver);
      hDriver = INVALID_HANDLE_VALUE;
      osError = ENOENT;
      return FALSE;
    }
    deviceName = psprintf("%08X", dwDeviceId);
  }
  else {
    dwDeviceId = GetSerialNumber();
    if (dwDeviceId == 0) {
      CloseHandle(hDriver);
      hDriver = INVALID_HANDLE_VALUE;
      osError = ENOENT;
      return FALSE;
    }

    PINDEX prefixLen = strlen(DevicePathPrefix);
    if (strnicmp(devicePath, DevicePathPrefix, prefixLen) == 0)
      deviceName = devicePath.Mid(prefixLen);
    else
      deviceName = devicePath;
  }

  dwCardType = dwDeviceId >> 28;

  IoControl(IOCTL_Codec_SetKHz, 8000);
  IoControl(IOCTL_Idle_SetMasterGain, 15);
  IoControl(IOCTL_Filter_EnableDTMFDetect);
  IoControl(IOCTL_Speakerphone_AECOn);

  DWORD ver = 0;
  IoControl(IOCTL_VxD_GetVersion, 0, &ver);
  driverVersion = ((ver&0xff)<<24)|((ver&0xff00)<<8)|((ver>>16)&0xffff);

  PTRACE(2, "xJack\tOpened IxJ device \"" << GetName() << "\" version "
         << ((driverVersion>>24)&0xff  ) << '.'
         << ((driverVersion>>16)&0xff  ) << '.'
         << ( driverVersion     &0xffff));

  os_handle = 1;

  return TRUE;
}


BOOL OpalIxJDevice::Close()
{
  if (!IsOpen())
    return FALSE;

  RingLine(0, 0);
  StopRawCodec(0);
  SetLineToLineDirect(0, 1, TRUE); // Back to pass through mode

  if (GetOperatingSystem() == IsWindows9x)
    IoControl(IOCTL_Device_Close);
  else
    timeEndPeriod(2);

  deviceName = PString();

  if (hReadEvent != NULL) {
    CloseHandle(hReadEvent);
    hReadEvent = NULL;
  }
  if (hWriteEvent != NULL) {
    CloseHandle(hWriteEvent);
    hWriteEvent = NULL;
  }

  BOOL ok = CloseHandle(hDriver);
  hDriver = INVALID_HANDLE_VALUE;
  os_handle = -1;
  return ok;
}


PString OpalIxJDevice::GetName() const
{
  PStringStream name;

  name << "Internet ";

  switch (dwCardType) {
    case 0 :
    case 1 :
      name << "PhoneJACK";
      break;
    case 3 :
      name << "LineJACK";
      break;
    case 4 :
      name << "PhoneJACK-Lite";
      break;
    case 5 :
      name << "PhoneJACK-PCI";
      break;
    case 6 :
      name << "PhoneCARD";
      break;
    default :
      name << "xJACK";
  }

  name << " (" << deviceName << ')';

  return name;
}


unsigned OpalIxJDevice::GetLineCount()
{
  return IsLineJACK() ? NumLines : 1;
}


BOOL OpalIxJDevice::IsLinePresent(unsigned line, BOOL force)
{
  if (line >= GetLineCount())
    return FALSE;

  if (line != PSTNLine)
    return FALSE;

  int oldSlicState = -1;

  DWORD dwResult = 0;
  do {
    if (!IoControl(IOCTL_DevCtrl_GetLineTestResult, 0, &dwResult))
      return FALSE;
    if (dwResult == 0xffffffff || force) {
      if (dwResult == LINE_TEST_OK) {
        IoControl(IOCTL_DevCtrl_GetPotsToSlic, 0, &dwResult);
        oldSlicState = dwResult;
      }
      IoControl(IOCTL_DevCtrl_LineTest);
      dwResult = LINE_TEST_TESTING;
      force = FALSE;
    }
  } while (dwResult == LINE_TEST_TESTING);

  if (oldSlicState >= 0)
    IoControl(IOCTL_DevCtrl_SetPotsToSlic, oldSlicState);

  return dwResult == LINE_TEST_OK;
}


BOOL OpalIxJDevice::IsLineOffHook(unsigned line)
{
  if (line >= GetLineCount())
    return FALSE;

  DWORD dwResult = 0;

  if (line == PSTNLine) {
    if (!IoControl(IOCTL_DevCtrl_GetLineOnHook, 0, &dwResult))
      return FALSE;
    return dwResult == 0;
  }

  if (!IoControl(IsLineJACK() && IsLinePresent(PSTNLine)
                              ? IOCTL_DevCtrl_GetLinePhoneOnHook
			      : IOCTL_DevCtrl_GetOnHook, 0, &dwResult))
    return FALSE;

  BOOL newHookState = dwResult == 0;
  if (lastHookState != newHookState) {
    lastHookState = newHookState;
    hookTimeout = 250;
  }
  else {
    if (!hookTimeout.IsRunning())
      currentHookState = lastHookState;
  }

  return currentHookState;
}


BOOL OpalIxJDevice::SetLineOffHook(unsigned line, BOOL newState)
{
  if (line >= GetLineCount())
    return FALSE;

  if (line != PSTNLine)
    return FALSE;

  return IoControl(IOCTL_DevCtrl_LineSetOnHook, !newState);
}


BOOL OpalIxJDevice::HasHookFlash(unsigned line)
{
  if (line != POTSLine)
    return FALSE;

  DWORD dwResult;
  if (!IoControl(IOCTL_DevCtrl_GetFlashState, 0, &dwResult))
    return FALSE;

  if (lastFlashState == dwResult)
    return FALSE;

  lastFlashState = dwResult;
  return dwResult != 0;
}


BOOL OpalIxJDevice::IsLineRinging(unsigned line, DWORD * /*cadence*/)
{
  if (line >= GetLineCount())
    return FALSE;

  if (line != PSTNLine)
    return FALSE;

  if (ringTimeout.IsRunning())
    return TRUE;

  DWORD dwResult = 0;
  if (!IoControl(IOCTL_DevCtrl_LineGetRinging, 0, &dwResult) || dwResult == 0)
    return FALSE;

  ringTimeout = 2500;
  return TRUE;
}


BOOL OpalIxJDevice::RingLine(unsigned line, DWORD cadence)
{
  if (line >= GetLineCount())
    return FALSE;

  if (line != POTSLine)
    return FALSE;

  if (cadence == TRUE) {
    switch (countryCode) {
      case Australia :
        static unsigned AusRing[] = { 200, 400, 200, 2000 };
        return RingLine(line, PARRAYSIZE(AusRing), AusRing);
    }

    // United States ring pattern
    cadence = 0x00f;
  }

  IoControl(IOCTL_DevCtrl_SetPotsToSlic, 1);
  return IoControl(IOCTL_DevCtrl_SetRingPattern, cadence);
}


BOOL OpalIxJDevice::RingLine(unsigned line, PINDEX nCadence, unsigned * pattern)
{
  if (line >= GetLineCount())
    return FALSE;

  if (line != POTSLine)
    return FALSE;

  IoControl(IOCTL_DevCtrl_SetPotsToSlic, 1);


  DWORD dwReturn, dwSize;
  DWORD cadenceArray[10];
  cadenceArray[0] = (nCadence+1)/2; // Number of pairs
  cadenceArray[1] = (nCadence&1) == 0; // If odd then repeat last entry
  PINDEX i;
  for (i = 2; i < nCadence; i++)
    cadenceArray[i] = pattern[i-2];
  for (; i < PARRAYSIZE(cadenceArray); i++)
    cadenceArray[i] = 0;

  return IoControl(IOCTL_DevCtrl_SetRingCadence,
                   cadenceArray, sizeof(cadenceArray),
                   &dwReturn, sizeof(dwReturn), &dwSize);
}


BOOL OpalIxJDevice::IsLineDisconnected(unsigned line, BOOL checkForWink)
{
  if (line >= GetLineCount())
    return FALSE;

  if (line != PSTNLine)
    return !IsLineOffHook(line);

  if (checkForWink) {
    DWORD dwResult = 0;
    if (IoControl(IOCTL_DevCtrl_GetLineCallerOnHook, 0, &dwResult) && dwResult != 0) {
      PTRACE(3, "xJack\tDetected wink, line disconnected.");
      return TRUE;
    }
  }

/*  if ((IsToneDetected(line) & (DialTone|BusyTone)) != 0) { */
  if ((IsToneDetected(line) & BusyTone) != 0) {
    PTRACE(3, "xJack\tDetected dial or busy tone, line disconnected.");
    return TRUE;
  }

  return FALSE;
}


BOOL OpalIxJDevice::SetLineToLineDirect(unsigned line1, unsigned line2, BOOL connect)
{
  if (line1 >= GetLineCount() || line2 >= GetLineCount())
    return FALSE;

  if (line1 == line2)
    return FALSE;

  DWORD dwResult = 0;
  return IoControl(IOCTL_DevCtrl_SetPotsToSlic, connect ? 0 : 1, &dwResult) && dwResult != 0;
}


BOOL OpalIxJDevice::IsLineToLineDirect(unsigned line1, unsigned line2)
{
  if (line1 >= GetLineCount() || line2 >= GetLineCount())
    return FALSE;

  if (line1 == line2)
    return FALSE;

  // The IOCTL_DevCtrl_GetPotsToSlic is broken unless the line test has been
  // performed and there is a PSTN line present.
  if (!IsLinePresent(PSTNLine))
    return FALSE;

  DWORD dwResult = 1;
  if (!IoControl(IOCTL_DevCtrl_GetPotsToSlic, 0, &dwResult))
    return FALSE;

  return dwResult == 0;
}



static const struct {
  const char * mediaFormat;
  unsigned dspBitMask:3; // bit0=8020,bit1=8021,bit2=8022
  unsigned isG729:1;
  unsigned isG7231:1;
  unsigned vad:1;
  PINDEX frameSize;
  DWORD recordMode;
  DWORD recordRate;
  DWORD playbackMode;
  DWORD playbackRate;
} CodecInfo[] = {
  { OPAL_PCM16,         7, 0, 0, 0,   0, RECORD_MODE_16LINEAR,   0,                   PLAYBACK_MODE_16LINEAR,   0                     },
  { OPAL_G711_ULAW_64K, 7, 0, 0, 0,   0, RECORD_MODE_ULAW,       0,                   PLAYBACK_MODE_ULAW,       0                     },
  { OPAL_G711_ALAW_64K, 7, 0, 0, 0,   0, RECORD_MODE_ALAW,       0,                   PLAYBACK_MODE_ALAW,       0                     },
  { OPAL_G728,          2, 0, 0, 0,  20, RECORD_MODE_TRUESPEECH, RECORD_RATE_G728,    PLAYBACK_MODE_TRUESPEECH, PLAYBACK_RATE_G728    },
  { OPAL_G729,          6, 1, 0, 0,  10, RECORD_MODE_TRUESPEECH, RECORD_RATE_G729,    PLAYBACK_MODE_TRUESPEECH, PLAYBACK_RATE_G729    },
  { OPAL_G729AB,        6, 1, 0, 1,  10, RECORD_MODE_TRUESPEECH, RECORD_RATE_G729,    PLAYBACK_MODE_TRUESPEECH, PLAYBACK_RATE_G729    },

  // these two lines should be for the 5k3 codec, but this does not work properly in the driver so we lie
  { OPAL_G7231_5k3,     7, 0, 1, 0,  24, RECORD_MODE_TRUESPEECH, RECORD_RATE_G723_63, PLAYBACK_MODE_TRUESPEECH, PLAYBACK_RATE_G723_63 },
  { OPAL_G7231A_5k3,    7, 0, 1, 1,  24, RECORD_MODE_TRUESPEECH, RECORD_RATE_G723_63, PLAYBACK_MODE_TRUESPEECH, PLAYBACK_RATE_G723_63 },

  { OPAL_G7231_6k3,     7, 0, 1, 0,  24, RECORD_MODE_TRUESPEECH, RECORD_RATE_G723_63, PLAYBACK_MODE_TRUESPEECH, PLAYBACK_RATE_G723_63 },
  { OPAL_G7231A_6k3,    7, 0, 1, 1,  24, RECORD_MODE_TRUESPEECH, RECORD_RATE_G723_63, PLAYBACK_MODE_TRUESPEECH, PLAYBACK_RATE_G723_63 },

};


OpalMediaFormat::List OpalIxJDevice::GetMediaFormats() const
{
  OpalMediaFormat::List codecs;

  OpalIxJDevice * unconstThis = (OpalIxJDevice *)this;

  DWORD dwIdCode = 0;
  if (unconstThis->IoControl(IOCTL_DevCtrl_GetIdCode, 0, &dwIdCode)) {
    unsigned dspBit = 1 << (dwIdCode&3);
    PINDEX codec = PARRAYSIZE(CodecInfo);
    while (codec-- > 0) {
      BOOL add = (CodecInfo[codec].dspBitMask&dspBit) != 0;
      if (add && CodecInfo[codec].isG729) {
        DWORD hasG729 = 1;
        add = unconstThis->IoControl(IOCTL_Device_GetG729Enable, 0, &hasG729) && hasG729;
      }
      if (add)
        codecs.Append(new OpalMediaFormat(CodecInfo[codec].mediaFormat));
    }
  }

  return codecs;
}


static PINDEX FindCodec(const OpalMediaFormat & mediaFormat)
{
  for (PINDEX codecType = 0; codecType < PARRAYSIZE(CodecInfo); codecType++) {
    if (mediaFormat == CodecInfo[codecType].mediaFormat)
      return codecType;
  }

  return P_MAX_INDEX;
}


BOOL OpalIxJDevice::SetReadFormat(unsigned line, const OpalMediaFormat & mediaFormat)
{
  StopReadCodec(line);

  PWaitAndSignal mutex(readMutex);

  IoControl(IOCTL_Record_Stop);

  readCodecType = FindCodec(mediaFormat);
  if (readCodecType == P_MAX_INDEX) {
    PTRACE(1, "xJack\tUnsupported read codec requested: " << mediaFormat);
    return FALSE;
  }

  if (!writeStopped && readCodecType != writeCodecType) {
    PTRACE(1, "xJack\tAsymmetric codecs requested: "
              "read=" << CodecInfo[readCodecType].mediaFormat
           << " write=" << CodecInfo[writeCodecType].mediaFormat);
    return FALSE;
  }

  PTRACE(3, "xJack\tSetReadFormat(" << CodecInfo[readCodecType].mediaFormat << ')');

  if (!IoControl(IOCTL_Codec_SetKHz, 8000))
    return FALSE;

  if (!IoControl(IOCTL_Record_SetBufferChannelLimit, 1))
    return FALSE;

  DWORD mode;
  do {
    if (!IoControl(IOCTL_Record_SetRECMODE, CodecInfo[readCodecType].recordMode))
      return FALSE;
    if (!IoControl(IOCTL_Record_GetRECMODE, 0, &mode))
      return FALSE;
    PTRACE_IF(3, mode != CodecInfo[readCodecType].recordMode,
              "xJack\tSetRECMODE failed (" << mode << " -> " <<
              CodecInfo[readCodecType].recordMode << "), retrying");
  } while (mode != CodecInfo[readCodecType].recordMode);

  DWORD rate;
  do {
    if (!IoControl(IOCTL_Record_SetRate, CodecInfo[readCodecType].recordRate))
      return FALSE;
    if (!IoControl(IOCTL_Record_GetRate, 0, &rate))
      return FALSE;
    PTRACE_IF(3, rate != CodecInfo[readCodecType].recordRate,
              "xJack\tRecord_SetRate failed (" << rate << " -> " <<
              CodecInfo[readCodecType].recordRate << "), retrying");
  } while (rate != CodecInfo[readCodecType].recordRate);

  readFrameSize = CodecInfo[readCodecType].frameSize;
  if (readFrameSize == 0) {
    DWORD frameWords;
    if (IoControl(IOCTL_Record_GetFrameSize, 0, &frameWords))
      readFrameSize = frameWords*2;
    else {
      PTRACE(1, "xJack\tCould not get record frame size.");
      return FALSE;
    }
  }

  SetVAD(line, CodecInfo[readCodecType].vad);

  if (!IoControl(driverVersion >= NEW_DRIVER_VERSION ? IOCTL_Record_Start
                                                     : IOCTL_Record_Start_Old))
    return FALSE;

  readStopped = FALSE;

  return TRUE;
}


BOOL OpalIxJDevice::SetWriteFormat(unsigned line, const OpalMediaFormat & mediaFormat)
{
  StopWriteCodec(line);

  PWaitAndSignal mutex(writeMutex);

  IoControl(IOCTL_Playback_Stop);

  writeCodecType = FindCodec(mediaFormat);
  if (writeCodecType == P_MAX_INDEX) {
    PTRACE(1, "xJack\tUnsupported write codec requested: " << mediaFormat);
    return FALSE;
  }

  if (!readStopped && writeCodecType != readCodecType) {
    PTRACE(1, "xJack\tAsymmetric codecs requested: "
              "read=" << CodecInfo[readCodecType].mediaFormat
           << " write=" << CodecInfo[writeCodecType].mediaFormat);
    return FALSE;
  }

  PTRACE(3, "xJack\tSetWriteFormat(" << CodecInfo[writeCodecType].mediaFormat << ')');

  if (!IoControl(IOCTL_Codec_SetKHz, 8000))
    return FALSE;

  if (!IoControl(IOCTL_Playback_SetBufferChannelLimit, 1))
    return FALSE;

  DWORD mode;
  do {
    if (!IoControl(IOCTL_Playback_SetPLAYMODE, CodecInfo[writeCodecType].playbackMode))
      return FALSE;
    if (!IoControl(IOCTL_Playback_GetPLAYMODE, 0, &mode))
      return FALSE;
    PTRACE_IF(2, mode != CodecInfo[writeCodecType].playbackMode,
              "xJack\tSetPLAYMODE failed (" << mode << " -> " <<
              CodecInfo[writeCodecType].playbackMode << "), retrying");
  } while (mode != CodecInfo[writeCodecType].playbackMode);

  DWORD rate;
  do {
    if (!IoControl(IOCTL_Playback_SetRate, CodecInfo[writeCodecType].playbackRate))
      return FALSE;
    if (!IoControl(IOCTL_Playback_GetRate, 0, &rate))
      return FALSE;
    PTRACE_IF(2, rate != CodecInfo[writeCodecType].playbackRate,
              "xJack\tPlayback_SetRate failed (" << rate << " -> " <<
              CodecInfo[writeCodecType].playbackRate << "), retrying");
  } while (rate != CodecInfo[writeCodecType].playbackRate);

  writeFrameSize = CodecInfo[writeCodecType].frameSize;
  if (writeFrameSize == 0) {
    DWORD frameWords;
    if (IoControl(IOCTL_Playback_GetFrameSize, 0, &frameWords))
      writeFrameSize = frameWords*2;
    else {
      PTRACE(1, "xJack\tCould not get playback frame size.");
      return FALSE;
    }
  }

  SetVAD(line, CodecInfo[writeCodecType].vad);

  if (!IoControl(driverVersion >= NEW_DRIVER_VERSION ? IOCTL_Playback_Start
                                                     : IOCTL_Playback_Start_Old))
    return FALSE;

  writeStopped = FALSE;
  return TRUE;
}


OpalMediaFormat OpalIxJDevice::GetReadFormat(unsigned)
{
  if (readCodecType == P_MAX_INDEX)
    return "";
  return CodecInfo[readCodecType].mediaFormat;
}


OpalMediaFormat OpalIxJDevice::GetWriteFormat(unsigned)
{
  if (writeCodecType == P_MAX_INDEX)
    return "";
  return CodecInfo[writeCodecType].mediaFormat;
}


BOOL OpalIxJDevice::SetRawCodec(unsigned)
{
  if (inRawMode)
    return FALSE;

  PTRACE(3, "xJack\tSetRawCodec()");

  // Default to 30ms frames of 16 bit PCM data
  readFrameSize = 480;
  writeFrameSize = 480;

  if (hReadEvent == NULL)
    hReadEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (hWriteEvent == NULL)
    hWriteEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

  HANDLE hEventArr[2];

  if (GetOperatingSystem() == IsWindows9x) {
    CHAR K32Path[MAX_PATH];
    HINSTANCE hK32;
    HANDLE (WINAPI *OpenVxDHandle)(HANDLE);

    GetSystemDirectory(K32Path, MAX_PATH);
    strcat(K32Path, "\\kernel32.dll");
    hK32 = LoadLibrary(K32Path);

    OpenVxDHandle = (HANDLE(WINAPI *)(HANDLE))GetProcAddress(hK32, "OpenVxDHandle");
    hEventArr[0] = OpenVxDHandle(hReadEvent);
    hEventArr[1] = OpenVxDHandle(hWriteEvent);
    FreeLibrary(hK32);
  }
  else
  {
    hEventArr[0] = hReadEvent;
    hEventArr[1] = hWriteEvent;
  }

  readMutex.Wait();
  writeMutex.Wait();

  DWORD dwReturn, dwBytesReturned;
  inRawMode = IoControl(IOCTL_Fax_Start,
                        hEventArr, sizeof(hEventArr),
                        &dwReturn, sizeof(dwReturn), &dwBytesReturned);
  readCodecType = writeCodecType = 0;
  readStopped = writeStopped = !inRawMode;

  readMutex.Signal();
  writeMutex.Signal();

  return inRawMode;
}


BOOL OpalIxJDevice::StopReadCodec(unsigned line)
{
  if (inRawMode)
    return StopRawCodec(line);

  PTRACE(3, "xJack\tStopping read codec");

  readMutex.Wait();
  if (!readStopped) {
    readStopped = TRUE;
    IoControl(IOCTL_Record_Stop);
  }
  readMutex.Signal();

  return OpalLineInterfaceDevice::StopReadCodec(line);
}


BOOL OpalIxJDevice::StopWriteCodec(unsigned line)
{
  if (inRawMode)
    return StopRawCodec(line);

  PTRACE(3, "xJack\tStopping write codec");

  writeMutex.Wait();
  if (!writeStopped) {
    writeStopped = TRUE;
    IoControl(IOCTL_Playback_Stop);
  }
  writeMutex.Signal();

  return OpalLineInterfaceDevice::StopWriteCodec(line);
}


BOOL OpalIxJDevice::StopRawCodec(unsigned line)
{
  if (!inRawMode) {
    BOOL ok = StopReadCodec(line);
    return StopWriteCodec(line) && ok;
  }

  PTRACE(3, "xJack\tStopping raw codec");

  readMutex.Wait();
  writeMutex.Wait();
  readStopped = TRUE;
  writeStopped = TRUE;
  BOOL ok = IoControl(IOCTL_Fax_Stop);
  readMutex.Signal();
  writeMutex.Signal();

  inRawMode = FALSE;

  OpalLineInterfaceDevice::StopReadCodec(line);
  OpalLineInterfaceDevice::StopWriteCodec(line);
  return ok;
}


PINDEX OpalIxJDevice::GetReadFrameSize(unsigned)
{
  return readFrameSize;
}


BOOL OpalIxJDevice::SetReadFrameSize(unsigned, PINDEX size)
{
  if (!inRawMode)
    return FALSE;

  readFrameSize = size;
  return TRUE;
}


PINDEX OpalIxJDevice::GetWriteFrameSize(unsigned)
{
  return writeFrameSize;
}


BOOL OpalIxJDevice::SetWriteFrameSize(unsigned, PINDEX size)
{
  if (!inRawMode)
    return FALSE;

  writeFrameSize = size;
  return TRUE;
}


BOOL OpalIxJDevice::ReadFrame(unsigned, void * buffer, PINDEX & count)
{
  count = 0;

  PWaitAndSignal mutex(readMutex);
  if (readStopped)
    return FALSE;

  DWORD dwBytesReturned = 0;
  if (inRawMode) {
    if (WaitForSingleObjectEx(hReadEvent, 1000, TRUE) != WAIT_OBJECT_0) {
      osError = EAGAIN;
      PTRACE(1, "xJack\tRead Timeout!");
      return FALSE;
    }
    IoControl(IOCTL_Fax_Read, NULL, 0, buffer, readFrameSize, &dwBytesReturned);
    count = (PINDEX)dwBytesReturned;
    return TRUE;
  }

  BOOL reblockG729 = CodecInfo[readCodecType].isG729;
  WORD temp_frame_buffer[6];

  PWin32Overlapped overlap;
  if (!IoControl(IOCTL_Device_Read, NULL, 0,
                 reblockG729 ? temp_frame_buffer         : buffer,
                 reblockG729 ? sizeof(temp_frame_buffer) : readFrameSize,
                 &dwBytesReturned, &overlap))
    return FALSE;

  if (reblockG729) {
    switch (temp_frame_buffer[0]) {
      case 1 :
        memcpy(buffer, &temp_frame_buffer[1], 10);
        count = 10;
        break;
      case 2 :
        if (CodecInfo[readCodecType].vad) {
          *(WORD *)buffer = temp_frame_buffer[1];
          count = 2;
        }
        else {
          memset(buffer, 0, 10);
          count = 10;
        }
        break;
      default : // Must be old driver
        memcpy(buffer, temp_frame_buffer, 10);
        count = 10;
    }
  }
  else if (CodecInfo[readCodecType].isG7231) {
    // Pick out special cases for G.723.1 based codecs (variable length frames)
    static const PINDEX g723count[4] = { 24, 20, 4, 1 };
    count = g723count[(*(BYTE *)buffer)&3];
  }
  else
    count = (PINDEX)dwBytesReturned;

  return TRUE;
}


BOOL OpalIxJDevice::WriteFrame(unsigned, const void * buffer, PINDEX count, PINDEX & written)
{
  PWaitAndSignal mutex(writeMutex);
  if (writeStopped)
    return FALSE;

  DWORD dwResult = 0;
  DWORD dwBytesReturned = 0;

  if (inRawMode) {
    for (written = 0; written < count; written += dwResult) {
      if (WaitForSingleObjectEx(hWriteEvent, 1000, TRUE) != WAIT_OBJECT_0) {
        osError = EAGAIN;
        PTRACE(1, "xJack\tWrite Timeout!");
        return FALSE;
      }
      IoControl(IOCTL_Fax_Write, ((BYTE *)buffer)+written, count-written,
                &dwResult, sizeof(dwResult), &dwBytesReturned);
    }
    return TRUE;
  }

  WORD temp_frame_buffer[12];
  PINDEX bytesToWrite;

  if (CodecInfo[writeCodecType].isG7231) {
    // Pick out special cases for G.723.1 based codecs (variable length frames)
    switch ((*(BYTE *)buffer)&3) {
      case 0 : // 6.3kbps rate frame
        written = 24;
        break;
      case 1 : // 5.3kbps rate frame
        written = 20;
        break;
      case 2 : // a Silence Insertion Descriptor
        memset(temp_frame_buffer, 0, sizeof(temp_frame_buffer));
        *(DWORD *)(temp_frame_buffer) = *(const DWORD *)buffer;
        buffer = temp_frame_buffer;
        written = 4;
        break;
      case 3 : // repeat last CNG frame
        // Check for frame erasure command
        if (memcmp(buffer, "\xff\xff\xff\xff", 4) == 0)
          written = 24;
        else {
          memset(temp_frame_buffer, 0, sizeof(temp_frame_buffer));
          temp_frame_buffer[0] = 3;
          buffer = temp_frame_buffer;
          written = 1;
        }
        break;
    }
    bytesToWrite = 24;
  }
  else if (CodecInfo[writeCodecType].isG729) {
    if (count == 2) {
      PTRACE_IF(2, !CodecInfo[readCodecType].vad,
                "xJack\tG.729B frame received, but not selected.");
      temp_frame_buffer[0] = 2;
      temp_frame_buffer[1] = *(const WORD *)buffer;
      memset(&temp_frame_buffer[2], 0, 8);
      written = 2;
    }
    else {
      if (memcmp(buffer, "\0\0\0\0\0\0\0\0\0", 10) == 0) {
#if 0
        memset(temp_frame_buffer, 0, 12);
#else
        // We really should be sending a full frame of zeros here, but the codec
        // makes a clicking sound if you do so send annex B CNG frames instead.
        temp_frame_buffer[0] = 2;
        memset(&temp_frame_buffer[1], 0, 10);
#endif
      }
      else {
        temp_frame_buffer[0] = 1;
        memcpy(&temp_frame_buffer[1], buffer, 10);
      }
      written = 10;
    }
    buffer = temp_frame_buffer;
    bytesToWrite = 12;
  }
  else {
    bytesToWrite = writeFrameSize;
    written = bytesToWrite;
  }

  if (count < written) {
    osError = EINVAL;
    PTRACE(1, "xJack\tWrite of too small a buffer");
    return FALSE;
  }

  PWin32Overlapped overlap;
  return IoControl(IOCTL_Device_Write, (void *)buffer, bytesToWrite,
                   &dwResult, sizeof(dwResult), &dwBytesReturned, &overlap);
}


unsigned OpalIxJDevice::GetAverageSignalLevel(unsigned, BOOL playback)
{
  DWORD dwLevel;
  if (!IoControl(playback ? IOCTL_Playback_GetAvgPlaybackLevel
                          : IOCTL_Record_GetAvgRecordLevel,
                 0, &dwLevel))
    return UINT_MAX;

  return dwLevel;
}


BOOL OpalIxJDevice::EnableAudio(unsigned line, BOOL enable)
{
  if (line >= GetLineCount())
    return FALSE;

  DWORD dwSource = ANALOG_SOURCE_SPEAKERPHONE;

  if (enable) {
    if (enabledAudioLine != line) {
      if (enabledAudioLine != UINT_MAX && exclusiveAudioMode) {
        PTRACE(3, "xJack\tEnableAudio on port when already enabled other port.");
        return FALSE;
      }
      enabledAudioLine = line;
    }
    dwSource = line == POTSLine ? ANALOG_SOURCE_POTSPHONE : ANALOG_SOURCE_PSTNLINE;
  }
  else
    enabledAudioLine = UINT_MAX;

  if (!IsLineJACK())
    return IoControl(IOCTL_DevCtrl_SetAnalogSource, dwSource);

  BOOL connected = IsLineToLineDirect(POTSLine, PSTNLine);
  IoControl(IOCTL_DevCtrl_SetLineJackMode,
                 dwSource == ANALOG_SOURCE_PSTNLINE ? LINEJACK_MODE_LINEJACK
                                                    : LINEJACK_MODE_PHONEJACK);
  SetLineToLineDirect(POTSLine, PSTNLine, connected);

  if (dwSource != ANALOG_SOURCE_PSTNLINE) {
    if (!IoControl(IOCTL_DevCtrl_SetAnalogSource, dwSource))
      return FALSE;
  }

  InternalSetVolume(TRUE, RecordMicrophone,    -1, dwSource != ANALOG_SOURCE_SPEAKERPHONE);
  InternalSetVolume(TRUE, RecordPhoneIn,       -1, dwSource != ANALOG_SOURCE_POTSPHONE);
  InternalSetVolume(FALSE,PlaybackPhoneOut,    -1, dwSource != ANALOG_SOURCE_POTSPHONE);
  InternalSetVolume(TRUE, RecordPhoneLineIn,   -1, dwSource != ANALOG_SOURCE_PSTNLINE);
  InternalSetVolume(FALSE,PlaybackPhoneLineOut,-1, dwSource != ANALOG_SOURCE_PSTNLINE);
  InternalSetVolume(FALSE,PlaybackWave,        -1, FALSE);

  return TRUE;
}


BOOL OpalIxJDevice::IsAudioEnabled(unsigned line)
{
  return enabledAudioLine == line;
}


BOOL OpalIxJDevice::InternalSetVolume(BOOL record, unsigned id, int volume, int mute)
{
  MIXER_LINE mixer;
  mixer.dwLineID = id;

  DWORD dwSize = 0;
  if (!IoControl(record ? IOCTL_Mixer_GetRecordLineControls
                        : IOCTL_Mixer_GetPlaybackLineControls,
                 &mixer, sizeof(mixer), &mixer, sizeof(mixer), &dwSize))
    return FALSE;

  if (volume >= 0) {
    if (volume >= 100)
      mixer.dwRightVolume = 65535;
    else
      mixer.dwRightVolume = volume*65536/100;
    mixer.dwLeftVolume = mixer.dwRightVolume;
  }
  if (mute >= 0)
    mixer.dwMute = mute != 0;

  DWORD dwReturn;
  return IoControl(record ? IOCTL_Mixer_SetRecordLineControls
                          : IOCTL_Mixer_SetPlaybackLineControls,
                   &mixer, sizeof(mixer), &dwReturn, sizeof(dwReturn), &dwSize);
}


BOOL OpalIxJDevice::SetRecordVolume(unsigned line, unsigned volume)
{
  if (IsLineJACK()) {
    if (!InternalSetVolume(TRUE,
                           line == POTSLine ? RecordPhoneIn : RecordPhoneLineIn,
                           volume,
                           -1))
      return FALSE;
  }

  return InternalSetVolume(TRUE, RecordMaster, volume, -1);
}


BOOL OpalIxJDevice::SetPlayVolume(unsigned line, unsigned volume)
{
  if (IsLineJACK()) {
    if (!InternalSetVolume(FALSE,
                           line == POTSLine ? PlaybackPhoneOut : PlaybackPhoneLineOut,
                           volume,
                           -1))
      return FALSE;
  }

  return InternalSetVolume(FALSE, PlaybackMaster, volume, -1);
}


BOOL OpalIxJDevice::GetRecordVolume(unsigned, unsigned & volume)
{
  MIXER_LINE mixer;
  mixer.dwLineID = 0;

  DWORD dwSize = 0;
  if (!IoControl(IOCTL_Mixer_GetRecordLineControls,
                 &mixer, sizeof(mixer), &mixer, sizeof(mixer), &dwSize))
    return FALSE;

  if (mixer.dwLeftVolume > 65208) // 99.5%
    volume = 100;
  else
    volume = mixer.dwLeftVolume*100/65536;
  return TRUE;
}


BOOL OpalIxJDevice::GetPlayVolume(unsigned, unsigned & volume)
{
  MIXER_LINE mixer;
  mixer.dwLineID = 0;

  DWORD dwSize = 0;
  if (!IoControl(IOCTL_Mixer_GetPlaybackLineControls,
                 &mixer, sizeof(mixer), &mixer, sizeof(mixer), &dwSize))
    return FALSE;

  if (mixer.dwLeftVolume > 65208) // 99.5%
    volume = 100;
  else
    volume = mixer.dwLeftVolume*100/65536;
  return TRUE;
}


OpalLineInterfaceDevice::AECLevels OpalIxJDevice::GetAEC(unsigned)
{
  DWORD level = AECOff;
  IoControl(IOCTL_Speakerphone_GetAEC, 0, &level);
  return (AECLevels)level;
}


BOOL OpalIxJDevice::SetAEC(unsigned, AECLevels level)
{
  return IoControl(IOCTL_Speakerphone_SetAEC, level);
}


unsigned OpalIxJDevice::GetWinkDuration(unsigned)
{
  DWORD level = 0;
  IoControl(IOCTL_DevCtrl_GetLineWinkDetTime, 0, &level);
  return (unsigned)level;
}


BOOL OpalIxJDevice::SetWinkDuration(unsigned, unsigned winkDuration)
{
  return IoControl(IOCTL_DevCtrl_SetLineWinkDetTime, winkDuration);
}


BOOL OpalIxJDevice::GetVAD(unsigned)
{
  return vadEnabled;
}


BOOL OpalIxJDevice::SetVAD(unsigned, BOOL enable)
{
  PTRACE(3, "xJack\tSet VAD " << (enable ? "on" : "off"));
  vadEnabled = enable;
  return IoControl(enable ? IOCTL_Record_EnableVAD : IOCTL_Record_DisableVAD);
}


BOOL OpalIxJDevice::GetCallerID(unsigned, PString & idString, BOOL full)
{
  idString = PString();

  BYTE buffer[512];
  buffer[0] = 0;
  DWORD dwBytesReturned;
  if (!IoControl(IOCTL_DevCtrl_LineGetCallerID,
                 buffer, sizeof(buffer),
                 buffer, sizeof(buffer),
                 &dwBytesReturned))
    return FALSE;

  PTRACE_IF(3, buffer[0] != 0, "xJack\tCaller ID:\n"
            << hex << setprecision(2)
            << PBYTEArray(buffer, dwBytesReturned)
            << dec);

  PString name, timeStr;

  switch (buffer[0]) {
    case 4 : // Single message
      timeStr = PString((char *)&buffer[2], 8);
      idString = PString((char *)&buffer[10], buffer[1]-8);
      break;

    case 128 : {
      PINDEX totalLength = buffer[1];
      PINDEX pos = 2;
      while (pos < totalLength) {
        switch (buffer[pos]) {
          case 1 :
            timeStr = PString((char *)&buffer[pos+2], buffer[pos+1]);
            break;
          case 2 :
            idString = PString((char *)&buffer[pos+2], buffer[pos+1]);
            break;
          case 7 :
            name = PString((char *)&buffer[pos+2], buffer[pos+1]);
            break;
        }
        pos += buffer[pos+1]+2;
      }
      break;
    }

    default :
      return FALSE;
  }

  if (full && !timeStr.IsEmpty()) {
    PTime now;
    int minute = timeStr(6,7).AsUnsigned() % 60;
    int hour   = timeStr(4,5).AsUnsigned() % 24;
    int day    = timeStr(2,3).AsUnsigned();
    if (day < 1)
      day = 1;
    else if (day > 31)
      day = 31;
    int month  = timeStr(0,1).AsUnsigned();
    if (month < 1)
      month = 1;
    else if (month > 12)
      month = 12;

    PTime theTime(0, minute, hour, day, month, now.GetYear());
    idString += '\t' + theTime.AsString(PTime::ShortDateTime) + '\t' + name;
  }

  return TRUE;
}


BOOL OpalIxJDevice::SetCallerID(unsigned line, const PString & idString)
{
  if (line != POTSLine)
    return FALSE;

  if (idString.IsEmpty())
    return TRUE;

  PString name, number;
  PTime theTime;

  PStringArray fields = idString.Tokenise('\t', TRUE);
  switch (fields.GetSize()) {
    case 3 :
      name = fields[2];
    case 2 :
      theTime = PTime(fields[1]);
    case 1 :
     number = fields[0];
     break;
    default :
      return FALSE;
  }

  PINDEX numberLength = number.GetLength();
  PINDEX nameLength = name.GetLength();

  char buffer[256];
  buffer[0] = 1;
  buffer[1] = '\x80';
  buffer[2] = (char)(14+numberLength+nameLength);
  buffer[3] = 1;
  buffer[4] = 8;
  sprintf(&buffer[5],
          "%02u%02u%02u%02u",
          theTime.GetMonth(),
          theTime.GetDay(),
          theTime.GetHour(),
          theTime.GetMinute());
  buffer[13] = 2;
  buffer[14] = (char)numberLength;
  strcpy(&buffer[15], number);
  buffer[15+numberLength] = 7;
  buffer[16+numberLength] = (char)nameLength;
  strcpy(&buffer[17+numberLength], name);

  DWORD dwReturn = 0;
  DWORD dwBytesReturned;
  return IoControl(IOCTL_FSK_SetMsgData,
                   buffer, 17+numberLength+nameLength,
                   &dwReturn, sizeof(dwReturn), &dwBytesReturned);
}


BOOL OpalIxJDevice::SendCallerIDOnCallWaiting(unsigned, const PString & /*idString*/)
{
  return FALSE;
}


BOOL OpalIxJDevice::SendVisualMessageWaitingIndicator(unsigned line, BOOL isOn)
{
  if (IsLineOffHook(line))
    return FALSE;

  BYTE buffer[] = { 0, 130, 3, 11, 1, 0 };
  if (isOn)
    buffer[5] = 255;
  DWORD dwReturn = 0;
  DWORD dwBytesReturned;
  return IoControl(IOCTL_FSK_SetMsgData,
                   buffer, sizeof(buffer),
                   &dwReturn, sizeof(dwReturn), &dwBytesReturned);
}


BOOL OpalIxJDevice::PlayDTMF(unsigned line,
                             const char * digits,
                             DWORD onTime, DWORD offTime)
{
  while (*digits != '\0') {
    DWORD dwToneIndex;
    int digit = toupper(*digits++);
    switch (digit) {
      case '0' :
        dwToneIndex = IDLE_TONE_0;
        break;
      case '1' :
        dwToneIndex = IDLE_TONE_1;
        break;
      case '2' :
        dwToneIndex = IDLE_TONE_2;
        break;
      case '3' :
        dwToneIndex = IDLE_TONE_3;
        break;
      case '4' :
        dwToneIndex = IDLE_TONE_4;
        break;
      case '5' :
        dwToneIndex = IDLE_TONE_5;
        break;
      case '6' :
        dwToneIndex = IDLE_TONE_6;
        break;
      case '7' :
        dwToneIndex = IDLE_TONE_7;
        break;
      case '8' :
        dwToneIndex = IDLE_TONE_8;
        break;
      case '9' :
        dwToneIndex = IDLE_TONE_9;
        break;
      case '*' :
        dwToneIndex = IDLE_TONE_STAR;
        break;
      case '#' :
        dwToneIndex = IDLE_TONE_POUND;
        break;
      case 'A' :
        dwToneIndex = IDLE_TONE_A;
        break;
      case 'B' :
        dwToneIndex = IDLE_TONE_B;
        break;
      case 'C' :
        dwToneIndex = IDLE_TONE_C;
        break;
      case 'D' :
        dwToneIndex = IDLE_TONE_D;
        break;
      case ',' :
        dwToneIndex = IDLE_TONE_NOTONE;
        Sleep(2000);
        break;
      default :
        if ('E' <= digit && digit <= ('E' + 11))
          dwToneIndex = (digit - 'E') + 13;
        else {
          dwToneIndex = IDLE_TONE_NOTONE;
          Sleep(onTime+offTime);
        }
        break;
    }

    if (dwToneIndex != IDLE_TONE_NOTONE)
      if (!InternalPlayTone(line, dwToneIndex, onTime, offTime, TRUE))
        return FALSE;
  }

  return TRUE;
}


char OpalIxJDevice::ReadDTMF(unsigned)
{
  DWORD dwNewDigit;
  if (!IoControl(IOCTL_Filter_GetDTMFDigit, lastDTMFDigit, &dwNewDigit))
    return '\0';

  if (dwNewDigit == 0 || dwNewDigit == lastDTMFDigit)
    return '\0';

  lastDTMFDigit = dwNewDigit;

  static char const dtmf[16] = {
    'D','1','2','3','4','5','6','7','8','9','*','0','#','A','B','C'
  };
  PTRACE(3, "xJack\tDetected DTMF tone: " << dtmf[dwNewDigit&0xf]);

  return dtmf[dwNewDigit&0xf];
}


BOOL OpalIxJDevice::GetRemoveDTMF(unsigned)
{
  DWORD result = FALSE;
  if (!IoControl(IOCTL_Record_GetDisableOnDTMFDetect, 0, &result))
    return FALSE;

  return result != 0;
}


BOOL OpalIxJDevice::SetRemoveDTMF(unsigned, BOOL state)
{
  return IoControl(IOCTL_Record_SetDisableOnDTMFDetect, state);
}


unsigned OpalIxJDevice::IsToneDetected(unsigned line)
{
  if (line >= GetLineCount())
    return NoTone;

  if (!EnableAudio(line, TRUE))
    return NoTone;

  int tones = NoTone;

  DWORD dwReturn = 0;
  if (IoControl(IOCTL_Filter_IsToneCadenceValid, 0, &dwReturn) && dwReturn != 0) 
    tones |= DialTone;

  dwReturn = 0;
  if (IoControl(IOCTL_Filter_IsToneCadenceValid, 1, &dwReturn) && dwReturn != 0) 
    tones |= RingTone;

  dwReturn = 0;
  if (IoControl(IOCTL_Filter_IsToneCadenceValid, 2, &dwReturn) && dwReturn != 0) 
    tones |= BusyTone;

  dwReturn = 0;
  if (IoControl(IOCTL_Filter_IsToneCadenceValid, 3, &dwReturn) && dwReturn != 0) 
    tones |= CNGTone;

  return tones;
}


BOOL OpalIxJDevice::SetToneFilterParameters(unsigned /*line*/,
                                            CallProgressTones tone,
                                            unsigned   lowFrequency,
                                            unsigned   highFrequency,
                                            PINDEX     numCadences,
                                            const unsigned * onTimes,
                                            const unsigned * offTimes)
{
  DWORD toneIndex;
  switch (tone) {
    case DialTone :
      toneIndex = 0;
      break;
    case RingTone :
      toneIndex = 1;
      break;
    case BusyTone :
      toneIndex = 2;
      break;
    case CNGTone :
      toneIndex = 3;
      break;
    default :
      PTRACE(1, "xJack\tCannot set filter for tone: " << tone);
      return FALSE;
  }

  if (numCadences > 0) {
    qthDetectToneCadence dtc;

    if (numCadences > PARRAYSIZE(dtc.element)) {
      PTRACE(1, "xJack\tToo many cadence elements: " << numCadences);
      return FALSE;
    }


    dtc.ulFilter = toneIndex;
    dtc.ulNumElements = numCadences;
    dtc.type = QTH_DETECT_TONE_TYPE_ADD;
    dtc.term = QTH_DETECT_TONE_REPEAT_ALL;
    dtc.ulTolerance = 10;  // in %
    dtc.ulMinDetectLoops = 1;
    memset(dtc.element, 0, sizeof(dtc.element));
    for (PINDEX i = 0; i < numCadences; i++) {
      dtc.element[i].ulOnTime = onTimes[i];
      dtc.element[i].ulOffTime = offTimes[i];
    }

    PTRACE(2, "xJack\tSetting cadence for tone index " << toneIndex
           << ", num=" << numCadences
           << ' ' << dtc.element[0].ulOnTime
           << '-' << dtc.element[0].ulOffTime);

    DWORD dwReturn = 0;
    DWORD dwBytesReturned;
    IoControl(IOCTL_Filter_DetectToneCadence, &dtc, sizeof(dtc),
              &dwReturn, sizeof(dwReturn), &dwBytesReturned, FALSE);
  }

  static struct FilterTableEntry {
    unsigned lowFrequency;
    unsigned highFrequency;
    unsigned predefinedFilterSet;  // 0 = custom
    short    coefficients[19];
  } const FilterTable[] = {
    {  300, 640, 4 },
    {  300, 500, 5 },
    { 1100,1100, 6 },
    {  350, 350, 7 },
    {  400, 400, 8 },
    {  480, 480, 9 },
    {  440, 440, 10},
    {  620, 620, 11},
    {  425, 425, 0, 30850,-32534,-504,0,504,30831,-32669,24303,-22080,24303,30994,-32673, 1905, -1811, 1905,5,129,17,0xff5  },
    {  350, 440, 0, 30634,-31533,-680,0,680,30571,-32277,12894,-11945,12894,31367,-32379,23820,-23104,23820,7,159,21,0x0FF5 },
    {  400, 450, 0, 30613,-32031,-618,0,618,30577,-32491, 9612, -8935, 9612,31071,-32524,21596,-20667,21596,7,159,21,0x0FF5 },
  };

  FilterTableEntry match = { 0, 0, UINT_MAX };

  PINDEX i;

  // Look for exact match
  for (i = 0; i < PARRAYSIZE(FilterTable); i++) {
    if (lowFrequency  == FilterTable[i].lowFrequency &&
        highFrequency == FilterTable[i].highFrequency) {
      match = FilterTable[i];
      break;
    }
  }

  if (match.predefinedFilterSet == UINT_MAX) {
    // If single frequency, make a band out of it, +/- 5%
    if (lowFrequency == highFrequency) {
      lowFrequency  -= lowFrequency/20;
      highFrequency += highFrequency/20;
    }

    // Try again looking for a band that is just a bit larger than required, no
    // more than twice the size required.
    for (i = 0; i < PARRAYSIZE(FilterTable); i++) {
      if (lowFrequency  > FilterTable[i].lowFrequency &&
          highFrequency < FilterTable[i].highFrequency &&
          2*(highFrequency - lowFrequency) >
                  (FilterTable[i].highFrequency - FilterTable[i].lowFrequency)) {
        match = FilterTable[i];
        break;
      }
    }
  }

  if (match.predefinedFilterSet == UINT_MAX) {
    PTRACE(1, "xJack\tInvalid frequency for fixed filter sets: "
            << lowFrequency << '-' << highFrequency);
    return FALSE;
  }

  struct {
    DWORD dwFilterNum;
    union {
      DWORD predefinedFilterSet;
      short coefficients[19];
    };
  } filterSet;
  PINDEX sizeOfFilterSet;

  if (match.predefinedFilterSet != 0) {
    filterSet.predefinedFilterSet = match.predefinedFilterSet;
    sizeOfFilterSet = sizeof(filterSet.dwFilterNum) + sizeof(filterSet.predefinedFilterSet);
  }
  else {
    memcpy(filterSet.coefficients, match.coefficients, sizeof(filterSet.coefficients));
    sizeOfFilterSet = sizeof(filterSet);
  }

  filterSet.dwFilterNum = toneIndex;

  PTRACE(2, "xJack\tSetting filter for tone index " << toneIndex
         << " freq: " << match.lowFrequency << '-' << match.highFrequency);

  DWORD dwReturn = 0;
  DWORD dwBytesReturned;
  return IoControl(IOCTL_Filter_ProgramFilter, &filterSet, sizeOfFilterSet,
                   &dwReturn, sizeof(dwReturn), &dwBytesReturned, FALSE);
}


BOOL OpalIxJDevice::PlayTone(unsigned line, CallProgressTones tone)
{
  switch (tone) {
    case DialTone :
      return InternalPlayTone(line, IDLE_TONE_DIAL, 0, 0, FALSE);
    case RingTone :
      return InternalPlayTone(line, IDLE_TONE_RING, 0, 0, FALSE);
    case BusyTone :
      return InternalPlayTone(line, IDLE_TONE_BUSY, 0, 0, FALSE);
    case ClearTone :
      return InternalPlayTone(line, IDLE_TONE_BUSY, 0, 0, FALSE);
    default :
      return InternalPlayTone(line, IDLE_TONE_NOTONE, 0, 0, FALSE);
  }
}


BOOL OpalIxJDevice::IsTonePlaying(unsigned)
{
  return PTimer::Tick() < toneSendCompletionTime;
}


BOOL OpalIxJDevice::StopTone(unsigned)
{
  PTRACE(3, "xJack\tStopping tones");

  return IoControl(IOCTL_Idle_StopTone);
}


BOOL OpalIxJDevice::InternalPlayTone(unsigned line,
                                     DWORD toneIndex,
                                     DWORD onTime, DWORD offTime,
                                     BOOL synchronous)
{
  StopTone(line);

  PTRACE(3, "xJack\tPlaying tone: "
         << toneIndex << ' ' << onTime << ' ' << offTime << ' ' << synchronous);

  IDLE_TONE tone;

  tone.dwToneIndex = toneIndex;
  tone.dwToneOnPeriod = onTime;
  tone.dwToneOffPeriod = offTime;
  tone.dwDuration = tone.dwToneOnPeriod+tone.dwToneOffPeriod;
  tone.dwMasterGain = 15;

  DWORD dwReturn = 0;
  DWORD dwBytesReturned;
  if (!IoControl(IOCTL_Idle_PlayTone,
                 &tone, sizeof(tone),
                 &dwReturn, sizeof(dwReturn), &dwBytesReturned) ||
      dwBytesReturned != sizeof(dwReturn) ||
      dwReturn == 0)
    return FALSE;

  toneSendCompletionTime = PTimer::Tick() + (int)tone.dwDuration - 1;
  if (synchronous)
    Sleep(tone.dwDuration);

  return TRUE;
}


BOOL OpalIxJDevice::SetCountryCode(T35CountryCodes country)
{
  OpalLineInterfaceDevice::SetCountryCode(country);

  // if a LineJack, the set the DAA coeffiecients
  if (!IsLineJACK())
    return FALSE;

  if (country == UnknownCountry)
    return TRUE;

  static struct {
    T35CountryCodes t35Code;
    DWORD           ixjCode;
  } ixjCountry[] = {
    { UnitedStates,  COEFF_US },
    { Australia,     COEFF_AUSTRALIA },
    { Czechoslovakia,COEFF_CZECH },
    { France,        COEFF_FRANCE },
    { Germany,       COEFF_GERMANY },
    { Italy,         COEFF_ITALY },
    { Japan,         COEFF_JAPAN },
    { KoreaRepublic, COEFF_SOUTH_KOREA },
    { NewZealand,    COEFF_NEW_ZEALAND },
    { Norway,        COEFF_NORWAY },
    { Philippines,   COEFF_PHILIPPINES },
    { Poland,        COEFF_POLAND },
    { SouthAfrica,   COEFF_SOUTH_AFRICA },
    { Sweden,        COEFF_SWEDEN },
    { UnitedKingdom, COEFF_UK }
  };

  PINDEX i;
  for (i = PARRAYSIZE(ixjCountry)-1; i > 0; i--) {
    if (ixjCountry[i].t35Code == countryCode)
      break;
  }

  PTRACE(2, "xJack\tSetting coefficient group for " << GetCountryCodeName(ixjCountry[i].t35Code));
  return IoControl(IOCTL_DevCtrl_SetCoefficientGroup, ixjCountry[i].ixjCode);
}


DWORD OpalIxJDevice::GetSerialNumber()
{
  if (GetOperatingSystem() == IsWindows9x)
    return deviceName.AsUnsigned(16);

  DWORD devId;
  if (IoControl(IOCTL_Device_GetSerialNumber, 0, &devId))
    return devId;

  return 0;
}


PStringArray OpalIxJDevice::GetDeviceNames()
{
  PStringArray array;

  PINDEX i;

  const char * DevicePath = "\\\\.\\QTJACKDevice%u";

  switch (GetOperatingSystem()) {
    case IsWindows2k :
      DevicePath = "\\\\.\\QTIWDMDevice%u";
      // Fall into NT case

    case IsWindowsNT :
      for (i = 0; i < 100; i++) {
        PString devpath;
        devpath.sprintf(DevicePath, i);
        HANDLE hDriver = CreateFile(devpath,
                                    GENERIC_READ,
                                    FILE_SHARE_WRITE,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                                    NULL);
        if (hDriver != INVALID_HANDLE_VALUE) {
          DWORD devId, bytesReturned;
          if (DeviceIoControl(hDriver, IOCTL_Device_GetSerialNumber,
                              NULL, 0, &devId, sizeof(devId), &bytesReturned, NULL) &&
              bytesReturned == sizeof(devId) && devId != 0) {
            devpath.sprintf(" (%08X)", devId);
            array.SetAt(array.GetSize(), new PCaselessString(devpath));
          }
          CloseHandle(hDriver);
        }
      }
      break;

    case IsWindows9x :
      PStringArray devices = PSoundChannel::GetDeviceNames(PSoundChannel::Player);
      for (i = 0; i < devices.GetSize(); i++) {
        PString dev = devices[i];
        if (dev.Find("Internet") != P_MAX_INDEX &&
              (dev.Find("JACK") != P_MAX_INDEX || dev.Find("PhoneCARD") != P_MAX_INDEX)) {
	  PINDEX lparen = dev.Find('(');
	  PINDEX rparen = dev.Find(')', lparen);
	  array.SetAt(array.GetSize(), new PCaselessString(dev(lparen+1, rparen-1)));
        }
      }
  }

  return array;
}


BOOL OpalIxJDevice::IoControl(DWORD dwIoControlCode,
                              DWORD inParam,
                              DWORD * outParam)
{
  DWORD dwDummy;
  if (outParam == NULL)
    outParam = &dwDummy;

  DWORD dwBytesReturned = 0;
  return IoControl(dwIoControlCode, &inParam, sizeof(DWORD),
                   outParam, sizeof(DWORD), &dwBytesReturned) &&
         dwBytesReturned == sizeof(DWORD);
}


BOOL OpalIxJDevice::IoControl(DWORD dwIoControlCode,
                               LPVOID lpInBuffer,
                               DWORD nInBufferSize,
                               LPVOID lpOutBuffer,
                               DWORD nOutBufferSize,
                               LPDWORD lpdwBytesReturned,
                               PWin32Overlapped * overlap)
{
  if (hDriver == INVALID_HANDLE_VALUE)
    return FALSE;

  DWORD newError = ERROR_SUCCESS;
  if (!DeviceIoControl(hDriver,
                      dwIoControlCode,
                      lpInBuffer,
                      nInBufferSize,
                      lpOutBuffer,
                      nOutBufferSize,
                      lpdwBytesReturned,
                      overlap)) {
    newError = ::GetLastError();
    while (newError == ERROR_IO_PENDING) {
      if (WaitForSingleObject(overlap->hEvent, 1000) != WAIT_OBJECT_0) {
        newError = ERROR_TIMEOUT;
        PTRACE(1, "xJack\tRead/Write Timeout!");
      }
      else if (GetOverlappedResult(hDriver, overlap, lpdwBytesReturned, FALSE))
        newError = ERROR_SUCCESS;
      else
        newError = ::GetLastError();
    }
  }

  PTRACE_IF(1, newError != ERROR_SUCCESS,
            "xJack\tError in DeviceIoControl, device=\"" << deviceName << "\", code=" << newError);

  osError = newError|PWIN32ErrorFlag;
  return newError == ERROR_SUCCESS;
}
#endif // HAS_IXJ


/////////////////////////////////////////////////////////////////////////////
