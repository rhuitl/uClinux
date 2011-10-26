/*
 * lid.cxx
 *
 * Line Interface Device
 *
 * Open Phone Abstraction Library
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
 * Contributor(s): ______________________________________.
 *
 * $Log: lid.cxx,v $
 * Revision 1.103  2004/07/19 14:16:10  csoutheren
 * Fixed problem with pragma dispayed as warning in gcc 3.5-20040704
 *
 * Revision 1.102  2004/06/01 05:48:03  csoutheren
 * Changed capability table to use abstract factory routines rather than internal linked list
 *
 * Revision 1.101  2004/05/19 07:38:24  csoutheren
 * Changed OpalMediaFormat handling to use abstract factory method functions
 *
 * Revision 1.100  2004/05/04 03:33:33  csoutheren
 * Added guards against comparing certain kinds of Capabilities
 *
 * Revision 1.99  2004/04/03 08:28:07  csoutheren
 * Remove pseudo-RTTI and replaced with real RTTI
 *
 * Revision 1.98  2003/08/18 23:56:01  dereksmithies
 * Fix typos in previous commit.
 *
 * Revision 1.97  2003/08/18 22:13:13  dereksmithies
 * Add Singapore Ring Cadence. Thanks to Steve.
 *
 * Revision 1.96  2003/06/03 10:27:42  rjongbloed
 * Added G.729 and G,729B detection from LID.
 *
 * Revision 1.95  2003/04/29 08:30:29  robertj
 * Fixed return type of get wink function.
 *
 * Revision 1.94  2003/04/28 01:47:52  dereks
 * Add ability to set/get wink duration for ixj device.
 *
 * Revision 1.93  2003/03/05 06:26:44  robertj
 * Added function to play a WAV file to LID, thanks Pietro Ravasio
 *
 * Revision 1.92  2003/02/13 23:33:36  dereks
 * Fix reporting of tonenames.
 *
 * Revision 1.91  2003/01/29 23:58:17  dereks
 * Fix typo in United Kingdom tone definition.
 *
 * Revision 1.90  2002/12/02 03:06:26  robertj
 * Fixed over zealous removal of code when NO_AUDIO_CODECS set.
 *
 * Revision 1.89  2002/11/05 04:27:12  robertj
 * Imported RingLine() by array from OPAL.
 *
 * Revision 1.88  2002/10/30 05:54:17  craigs
 * Fixed compatibilty problems with G.723.1 6k3 and 5k3
 *
 * Revision 1.87  2002/08/05 10:03:48  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.86  2002/07/01 02:56:17  dereks
 * Add PTRACE statements to  "IsToneDetected"
 *
 * Revision 1.85  2002/06/27 08:52:57  robertj
 * Fixed typo and naming convention for Cisco G.723.1 annex A capability.
 *
 * Revision 1.84  2002/06/26 05:45:45  robertj
 * Added capability for Cisco IOS non-standard name for G.723.1 Annex A so
 *   can now utilise SID frames with Cisco gateways.
 *
 * Revision 1.83  2002/06/25 08:30:13  robertj
 * Changes to differentiate between stright G.723.1 and G.723.1 Annex A using
 *   the OLC dataType silenceSuppression field so does not send SID frames
 *   to receiver codecs that do not understand them.
 *
 * Revision 1.82  2002/05/09 06:26:34  robertj
 * Added fuction to get the current audio enable state for line in device.
 * Changed IxJ EnableAudio() semantics so is exclusive, no direct switching
 *   from PSTN to POTS and vice versa without disabling the old one first.
 *
 * Revision 1.81  2002/01/23 06:13:56  robertj
 * Added filter function hooks to codec raw data channel.
 *
 * Revision 1.80  2002/01/23 01:58:28  robertj
 * Added function to determine if codecs raw data channel is native format.
 *
 * Revision 1.79  2002/01/13 23:57:04  robertj
 * Added mutex so can change raw data channel while reading/writing from codec.
 *
 * Revision 1.78  2001/12/14 04:33:53  craigs
 * Disabled 5.3k codec due to problems with Quicknet cards
 *
 * Revision 1.77  2001/12/11 04:27:28  craigs
 * Added support for 5.3kbps G723.1
 *
 * Revision 1.76  2001/09/21 02:52:19  robertj
 * Implemented static object for all "known" media formats.
 *
 * Revision 1.75  2001/09/11 01:24:36  robertj
 * Added conditional compilation to remove video and/or audio codecs.
 *
 * Revision 1.74  2001/09/10 03:06:29  robertj
 * Major change to fix problem with error codes being corrupted in a
 *   PChannel when have simultaneous reads and writes in threads.
 *
 * Revision 1.73  2001/08/06 03:08:57  robertj
 * Fission of h323.h to h323ep.h & h323con.h, h323.h now just includes files.
 *
 * Revision 1.72  2001/07/24 02:28:22  robertj
 * Added setting of tone filters for a handful of countries.
 *
 * Revision 1.71  2001/07/20 04:06:18  robertj
 * Removed old Cisco hack code for G.728, they now do it rigth!
 *
 * Revision 1.70  2001/07/19 05:54:30  robertj
 * Updated interface to xJACK drivers to utilise cadence and filter functions
 *   for dial tone, busy tone and ringback tone detection.
 *
 * Revision 1.69  2001/05/30 03:56:57  robertj
 * Fixed initial value of read deblocking offset on stopping codec.
 *
 * Revision 1.68  2001/05/25 07:55:26  robertj
 * Fixed problem with trace output of tone bits, thanks Vjacheslav Andrejev.
 *
 * Revision 1.67  2001/05/25 02:19:53  robertj
 * Fixed problem with codec data reblocking code not being reset when
 *   code is stopped and restarted, thanks Artis Kugevics
 *
 * Revision 1.66  2001/05/22 00:31:43  robertj
 * Changed to allow optional wink detection for line disconnect
 *
 * Revision 1.65  2001/05/14 05:56:28  robertj
 * Added H323 capability registration system so can add capabilities by
 *   string name instead of having to instantiate explicit classes.
 *
 * Revision 1.64  2001/05/11 04:43:43  robertj
 * Added variable names for standard PCM-16 media format name.
 *
 * Revision 1.63  2001/04/03 23:37:48  craigs
 * Added extra logging of country change functions
 *
 * Revision 1.62  2001/03/29 23:43:02  robertj
 * Added ability to get average signal level for both receive and transmit.
 * Changed silence detection to use G.723.1 SID frames as indicator of
 *   silence instead of using the average energy and adaptive threshold.
 *
 * Revision 1.61  2001/03/23 05:38:30  robertj
 * Added PTRACE_IF to output trace if a conditional is TRUE.
 *
 * Revision 1.60  2001/02/09 05:36:38  craigs
 * Added pragma implementation
 *
 * Revision 1.59  2001/01/28 06:29:55  yurik
 * WinCE-port - lid.h exists in SDK so we point to right one
 *
 * Revision 1.58  2001/01/25 07:27:16  robertj
 * Major changes to add more flexible OpalMediaFormat class to normalise
 *   all information about media types, especially codecs.
 *
 * Revision 1.57  2001/01/11 06:24:55  robertj
 * Fixed incorrect value for CNG frame
 *
 * Revision 1.56  2001/01/11 05:39:44  robertj
 * Fixed usage of G.723.1 CNG 1 byte frames.
 *
 * Revision 1.55  2001/01/11 03:51:14  robertj
 * Fixed bug in WriteBlock() flush, use actual frame size for last write.
 *
 * Revision 1.54  2001/01/04 06:39:51  robertj
 * Fixed bug in G.711 mode with xJACK cards if data is not a multiple of 10ms
 *    and some silence is transmitted, closes the logical channel.
 *
 * Revision 1.53  2000/12/17 22:08:20  craigs
 * Changed GetCountryCodeList to return PStringList
 *
 * Revision 1.52  2000/12/11 01:23:32  craigs
 * Added extra routines to allow country string manipulation
 *
 * Revision 1.51  2000/12/04 00:04:21  robertj
 * Changed G.711 "silence" to be 0xff to remove clicks from Quicknet cards,
 *
 * Revision 1.50  2000/11/30 08:48:36  robertj
 * Added functions to enable/disable Voice Activity Detection in LID's
 *
 * Revision 1.49  2000/11/30 03:12:00  robertj
 * Fixed bug in not resetting buffer offset on buffer flush.
 *
 * Revision 1.48  2000/11/29 22:08:31  craigs
 * Fixed problem with using WaitForToneDetect with 0 timeout
 *
 * Revision 1.47  2000/11/27 05:19:27  robertj
 * Fixed MSVC warning
 *
 * Revision 1.46  2000/11/27 00:19:39  robertj
 * Fixed bug in SetRawCodec, conditional around the wrong way
 *
 * Revision 1.45  2000/11/26 23:12:18  craigs
 * Added hook flash detection API
 *
 * Revision 1.44  2000/11/24 10:56:12  robertj
 * Added a raw PCM dta mode for generating/detecting standard tones.
 * Modified the ReadFrame/WriteFrame functions to allow for variable length codecs.
 *
 * Revision 1.43  2000/11/20 03:15:13  craigs
 * Changed tone detection API slightly to allow detection of multiple
 * simultaneous tones
 * Added fax CNG tone to tone list
 *
 * Revision 1.42  2000/11/03 06:25:37  robertj
 * Added flag to IsLinePresent() to force slow test, guarenteeing correct value.
 *
 * Revision 1.41  2000/10/31 03:21:02  robertj
 * Fixed bug that caused G.711 transmitter to continuously think there was silence.
 *
 * Revision 1.40  2000/10/16 09:45:10  robertj
 * Fixed recently introduced bug, caused artifacts when should be silent G.723.1
 *
 * Revision 1.39  2000/10/13 02:24:06  robertj
 * Moved frame reblocking code from LID channel to LID itself and added
 *    ReadBlock/WriteBlock functions to allow non integral frame sizes.
 *
 * Revision 1.38  2000/09/25 22:31:18  craigs
 * Added G.723.1 frame erasure capability
 *
 * Revision 1.37  2000/09/23 07:20:45  robertj
 * Fixed problem with being able to distinguish between sw and hw codecs in LID channel.
 *
 * Revision 1.36  2000/09/22 01:35:51  robertj
 * Added support for handling LID's that only do symmetric codecs.
 *
 * Revision 1.35  2000/09/01 00:15:21  robertj
 * Improved country code selection, can use 2 letter ISO codes or
 *    international dialling prefixes (with leading +) to select country.
 *
 * Revision 1.34  2000/08/31 13:14:40  craigs
 * Added functions to LID
 * More bulletproofing to Linux driver
 *
 * Revision 1.33  2000/08/30 23:24:36  robertj
 * Renamed string version of SetCountrCode() to SetCountryCodeName() to avoid
 *    C++ masking ancestor overloaded function when overriding numeric version.
 *
 * Revision 1.32  2000/07/13 16:03:25  robertj
 * Removed transmission of 1 byte repeat CNG frames in G.723.1 as it crashes other peoples stacks.
 *
 * Revision 1.31  2000/07/12 10:25:37  robertj
 * Renamed all codecs so obvious whether software or hardware.
 *
 * Revision 1.30  2000/07/09 15:23:00  robertj
 * Changed G.728 not to use Cisco hack. Cisco is just wrong!
 * Fixed output of silence in G.711 so works with any sized frame.
 *
 * Revision 1.29  2000/07/02 14:09:49  craigs
 * Fill uLaw and aLaw silence with 0x80 rather than 0x00
 *
 * Revision 1.28  2000/06/19 00:32:22  robertj
 * Changed functionf or adding all lid capabilities to not assume it is to an endpoint.
 *
 * Revision 1.27  2000/06/01 07:52:30  robertj
 * Changed some LID capability code back again so does not unneedfully break existing API.
 *
 * Revision 1.26  2000/05/30 10:19:28  robertj
 * Added function to add capabilities given a LID.
 * Improved LID capabilities so cannot create one that is not explicitly supported.
 *
 * Revision 1.25  2000/05/24 06:43:16  craigs
 * Added routines to get xJack volume
 * Fixed problem with receiving G>723.1 NULL frames
 *
 * Revision 1.24  2000/05/11 03:47:48  craigs
 * Added extra debugging
 *
 * Revision 1.23  2000/05/10 04:05:34  robertj
 * Changed capabilities so has a function to get name of codec, instead of relying on PrintOn.
 *
 * Revision 1.22  2000/05/04 12:56:43  robertj
 * Fixed GNU warning.
 *
 * Revision 1.21  2000/05/04 11:52:35  robertj
 * Added Packets Too Late statistics, requiring major rearrangement of jitter
 *    buffer code, not also changes semantics of codec Write() function slightly.
 *
 * Revision 1.20  2000/05/02 04:32:27  robertj
 * Fixed copyright notice comment.
 *
 * Revision 1.19  2000/04/30 03:57:14  robertj
 * Added PTRACE of read/write frame sizes required by LID.
 *
 * Revision 1.18  2000/04/19 02:04:30  robertj
 * BeOS port changes.
 *
 * Revision 1.17  2000/04/14 17:18:07  robertj
 * Fixed problem with error reporting from LID hardware.
 *
 * Revision 1.16  2000/04/10 17:45:11  robertj
 * Added higher level "DialOut" function for PSTN lines.
 * Added hook flash function.
 *
 * Revision 1.15  2000/04/05 18:04:12  robertj
 * Changed caller ID code for better portability.
 *
 * Revision 1.14  2000/04/03 19:25:14  robertj
 * Optimised G.711 codec to read/write larger chunks of data.
 *
 * Revision 1.13  2000/03/31 19:50:51  robertj
 * Fixed receiver loop being able to deal with RTP packets smaller than expected.
 *
 * Revision 1.12  2000/03/30 19:32:35  robertj
 * Added swab function which seems to be missing on Linux.
 *
 * Revision 1.11  2000/03/30 01:57:16  robertj
 * Added hacks so G.728 works with (I think) broken cisco gateways.
 *
 * Revision 1.10  2000/03/29 21:01:52  robertj
 * Changed codec to use number of frames rather than number of bytes.
 * Added function on LID to get available codecs.
 * Fixed codec table for G.729 codec
 *
 * Revision 1.9  2000/03/28 05:22:05  robertj
 * Fixed translation of text country code to numeric code.
 *
 * Revision 1.8  2000/03/23 23:36:49  robertj
 * Added more calling tone detection functionality.
 *
 * Revision 1.7  2000/03/21 03:06:50  robertj
 * Changes to make RTP TX of exact numbers of frames in some codecs.
 *
 * Revision 1.6  2000/01/13 12:39:29  robertj
 * Added string based country codes to LID.
 *
 * Revision 1.5  2000/01/13 04:03:46  robertj
 * Added video transmission
 *
 * Revision 1.4  2000/01/07 10:01:26  robertj
 * GCC/Linux compatibility
 *
 * Revision 1.3  2000/01/07 08:28:09  robertj
 * Additions and changes to line interface device base class.
 *
 * Revision 1.2  1999/12/29 01:18:07  craigs
 * Fixed problem with codecs other than G.711 not working after reorganisation
 *
 * Revision 1.1  1999/12/23 23:02:36  robertj
 * File reorganision for separating RTP from H.323 and creation of LID for VPB support.
 *
 */

#ifdef __GNUC__
#pragma implementation "lid.h"
#endif

#include <ptlib.h>

#ifndef _WIN32_WCE
#include "lid.h"
#else
#include "..\include\lid.h"
#endif
#include "h245.h"


#define new PNEW


///////////////////////////////////////////////////////////////////////////////

#if PTRACING
static const char * const CallProgressTonesNames[] = {
  "DialTone", "RingTone", "BusyTone", "ClearTone", "CNGTone"
};

ostream & operator<<(ostream & o, OpalLineInterfaceDevice::CallProgressTones t)
{
  PINDEX i = 0;    
  while ((1 << i) != t)
    i++;

  if (i < PARRAYSIZE(CallProgressTonesNames))
    return o << CallProgressTonesNames[i];
  else
    return o << "Unknown";
}

#endif


OpalLineInterfaceDevice::OpalLineInterfaceDevice()
{
  os_handle = -1;
  osError = 0;
  countryCode = UnknownCountry;
  readDeblockingOffset = P_MAX_INDEX;
  writeDeblockingOffset = 0;
}


BOOL OpalLineInterfaceDevice::IsOpen() const
{
  return os_handle >= 0;
}


BOOL OpalLineInterfaceDevice::Close()
{
  if (os_handle < 0)
    return FALSE;

  os_handle = -1;
  return TRUE;
}


BOOL OpalLineInterfaceDevice::IsLineTerminal(unsigned)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::IsLinePresent(unsigned, BOOL)
{
  return TRUE;
}


BOOL OpalLineInterfaceDevice::HookFlash(unsigned line, unsigned flashTime)
{
  if (!IsLineOffHook(line))
    return FALSE;

  if (!SetLineOnHook(line))
    return FALSE;

  PThread::Current()->Sleep(flashTime);

  return SetLineOffHook(line);
}


BOOL OpalLineInterfaceDevice::HasHookFlash(unsigned)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::IsLineRinging(unsigned, DWORD *)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::RingLine(unsigned, DWORD)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::RingLine(unsigned, PINDEX, unsigned *)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::IsLineDisconnected(unsigned line, BOOL)
{
  return IsToneDetected(line) == BusyTone;
}


BOOL OpalLineInterfaceDevice::SetLineToLineDirect(unsigned, unsigned, BOOL)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::IsLineToLineDirect(unsigned, unsigned)
{
  return FALSE;
}


OpalMediaFormat FindMediaFormat(RTP_DataFrame::PayloadTypes pt)
{
  const OpalMediaFormat::List & formats = OpalMediaFormat::GetRegisteredMediaFormats();
  for (PINDEX i = 0; i < formats.GetSize(); i++) {
    if (formats[i].GetPayloadType() == pt)
      return formats[i];
  }

  return "<<Unknown RTP payload type>>";
}


BOOL OpalLineInterfaceDevice::SetReadCodec(unsigned line,
                                           RTP_DataFrame::PayloadTypes codec)
{
  return SetReadFormat(line, FindMediaFormat(codec));
}


BOOL OpalLineInterfaceDevice::SetWriteCodec(unsigned line,
                                            RTP_DataFrame::PayloadTypes codec)
{
  return SetWriteFormat(line, FindMediaFormat(codec));
}


BOOL OpalLineInterfaceDevice::SetRawCodec(unsigned line)
{
  if (!SetReadFormat(line, OpalPCM16))
    return FALSE;

  if (SetWriteFormat(line, OpalPCM16))
    return TRUE;

  StopReadCodec(line);
  return FALSE;
}


BOOL OpalLineInterfaceDevice::StopReadCodec(unsigned)
{
  readDeblockingOffset = P_MAX_INDEX;
  return TRUE;
}


BOOL OpalLineInterfaceDevice::StopWriteCodec(unsigned)
{
  writeDeblockingOffset = 0;
  return TRUE;
}


BOOL OpalLineInterfaceDevice::StopRawCodec(unsigned line)
{
  BOOL ok = StopReadCodec(line);
  return StopWriteCodec(line) && ok;
}


BOOL OpalLineInterfaceDevice::SetReadFrameSize(unsigned, PINDEX)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::SetWriteFrameSize(unsigned, PINDEX)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::ReadBlock(unsigned line, void * buffer, PINDEX length)
{
  // Are reblocking the hardware frame sizes to those expected by the RTP packets.
  PINDEX frameSize = GetReadFrameSize(line);

  BYTE * bufferPtr = (BYTE *)buffer;

  PINDEX readBytes;
  while (length > 0) {
    if (readDeblockingOffset < frameSize) {
      PINDEX left = frameSize - readDeblockingOffset;
      if (left > length)
        left = length;
      memcpy(bufferPtr, &readDeblockingBuffer[readDeblockingOffset], left);
      readDeblockingOffset += left;
      bufferPtr += left;
      length -= left;
    }
    else if (length < frameSize) {
      BYTE * deblockPtr = readDeblockingBuffer.GetPointer(frameSize);
      if (!ReadFrame(line, deblockPtr, readBytes))
        return FALSE;
      readDeblockingOffset = 0;
    }
    else {
      if (!ReadFrame(line, bufferPtr, readBytes))
        return FALSE;
      bufferPtr += readBytes;
      length -= readBytes;
    }
  }

  return TRUE;
}


BOOL OpalLineInterfaceDevice::WriteBlock(unsigned line, const void * buffer, PINDEX length)
{
  PINDEX frameSize = GetWriteFrameSize(line);
  PINDEX written;

  // If zero length then flush any remaining data
  if (length == 0 && writeDeblockingOffset != 0) {
    SetWriteFrameSize(line, writeDeblockingOffset);
    BOOL ok = WriteFrame(line,
                         writeDeblockingBuffer.GetPointer(),
                         GetWriteFrameSize(line),
                         written);
    SetWriteFrameSize(line, frameSize);
    writeDeblockingOffset = 0;
    return ok;
  }

  const BYTE * bufferPtr = (const BYTE *)buffer;

  while (length > 0) {
    // If have enough data and nothing in the reblocking buffer, just send it
    // straight on to the device.
    if (writeDeblockingOffset == 0 && length >= frameSize) {
      if (!WriteFrame(line, bufferPtr, frameSize, written))
        return FALSE;
      bufferPtr += written;
      length -= written;
    }
    else {
      BYTE * savedFramePtr = writeDeblockingBuffer.GetPointer(frameSize);

      // See if new chunk gives us enough for one frames worth
      if ((writeDeblockingOffset + length) < frameSize) {
        // Nope, just copy bytes into buffer and return
        memcpy(savedFramePtr + writeDeblockingOffset, bufferPtr, length);
        writeDeblockingOffset += length;
        return TRUE;
      }

      /* Calculate bytes we want from the passed in buffer to fill a frame by
         subtracting from full frame width the amount we have so far. This also
         means the lastWriteCount is set to the correct amount of buffer we are
         grabbing this time around.
       */
      PINDEX left = frameSize - writeDeblockingOffset;
      memcpy(savedFramePtr + writeDeblockingOffset, bufferPtr, left);
      writeDeblockingOffset = 0;

      // Write the saved frame out
      if (!WriteFrame(line, savedFramePtr, frameSize, written))
        return FALSE;

      bufferPtr += left;
      length -= left;
    }
  }

  return TRUE;
}


unsigned OpalLineInterfaceDevice::GetAverageSignalLevel(unsigned, BOOL)
{
  return UINT_MAX;
}


BOOL OpalLineInterfaceDevice::EnableAudio(unsigned line, BOOL enabled)
{
  return line < GetLineCount() && enabled;
}


BOOL OpalLineInterfaceDevice::IsAudioEnabled(unsigned line)
{
  return line < GetLineCount();
}


BOOL OpalLineInterfaceDevice::SetRecordVolume(unsigned, unsigned)
{
  return FALSE;
}

BOOL OpalLineInterfaceDevice::GetRecordVolume(unsigned, unsigned &)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::SetPlayVolume(unsigned, unsigned)
{
  return FALSE;
}

BOOL OpalLineInterfaceDevice::GetPlayVolume(unsigned, unsigned &)
{
  return FALSE;
}


OpalLineInterfaceDevice::AECLevels OpalLineInterfaceDevice::GetAEC(unsigned)
{
  return AECError;
}


BOOL OpalLineInterfaceDevice::SetAEC(unsigned, AECLevels)
{
  return FALSE;
}

unsigned OpalLineInterfaceDevice::GetWinkDuration(unsigned)
{
  return 0;
}


BOOL OpalLineInterfaceDevice::SetWinkDuration(unsigned, unsigned)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::GetVAD(unsigned)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::SetVAD(unsigned, BOOL)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::GetCallerID(unsigned, PString & id, BOOL)
{
  id = PString();
  return FALSE;
}


BOOL OpalLineInterfaceDevice::SetCallerID(unsigned, const PString &)
{
  return FALSE;
}

BOOL OpalLineInterfaceDevice::SendCallerIDOnCallWaiting(unsigned, const PString &)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::SendVisualMessageWaitingIndicator(unsigned, BOOL)
{
  return FALSE;
}

BOOL OpalLineInterfaceDevice::PlayDTMF(unsigned, const char *, DWORD, DWORD)
{
  return FALSE;
}


char OpalLineInterfaceDevice::ReadDTMF(unsigned)
{
  return '\0';
}


BOOL OpalLineInterfaceDevice::GetRemoveDTMF(unsigned)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::SetRemoveDTMF(unsigned, BOOL)
{
  return FALSE;
}


unsigned OpalLineInterfaceDevice::IsToneDetected(unsigned)
{
  return NoTone;
}


unsigned OpalLineInterfaceDevice::WaitForToneDetect(unsigned line, unsigned timeout)
{
  PTRACE(2, "LID\tWaitForToneDetect");

  static const unsigned sampleRate = 25;

  timeout = (timeout+sampleRate-1)/sampleRate;

  unsigned retry = 0;
  do {
    unsigned tones = IsToneDetected(line);
    if (tones != NoTone) {
      PTRACE(2, "LID\tTone " << tones << " detected after " << (retry*sampleRate) << " ms");
      return tones;
    }

    PThread::Current()->Sleep(sampleRate);
    retry++;
  } while (retry < timeout);

  PTRACE(3, "LID\tTone detection timeout " << (retry*sampleRate) << " ms");
  return NoTone;
}


BOOL OpalLineInterfaceDevice::WaitForTone(unsigned line,
                                          CallProgressTones tone,
                                          unsigned timeout)
{
  PTRACE(3, "LID\tWaitFor the tone " << tone );
  BOOL res = WaitForToneDetect(line, timeout) & tone;
  PTRACE(3, "LID\tWaitFor the tone " << tone << 
	 " is successfull-" << (res ? "YES" : "No"));
  return res;
}


BOOL OpalLineInterfaceDevice::SetToneFilter(unsigned line,
                                            CallProgressTones tone,
                                            const PString & description)
{
  PString freqDesc, cadenceDesc;
  PINDEX colon = description.Find(':');
  if (colon == P_MAX_INDEX)
    freqDesc = description;
  else {
    freqDesc = description.Left(colon);
    cadenceDesc = description.Mid(colon+1);
  }

  unsigned low_freq, high_freq;
  PINDEX dash = freqDesc.Find('-');
  if (dash == P_MAX_INDEX)
    low_freq = high_freq = freqDesc.AsUnsigned();
  else {
    low_freq = freqDesc.Left(dash).AsUnsigned();
    high_freq = freqDesc.Mid(dash+1).AsUnsigned();
  }
  if (low_freq  < 100 || low_freq  > 3000 ||
      high_freq < 100 || high_freq > 3000 ||
      low_freq > high_freq) {
    PTRACE(1, "LID\tIllegal frequency specified: " << description);
    return FALSE;
  }

  PStringArray times = cadenceDesc.Tokenise("-");
  PINDEX numCadences = (times.GetSize()+1)/2;
  
  PUnsignedArray onTimes(numCadences), offTimes(numCadences);
  for (PINDEX i = 0; i < times.GetSize(); i++) {
    double time = atof(times[i]);
    if (time <= 0.01 || time > 10) {
      PTRACE(1, "LID\tIllegal cadence time specified: " << description);
      return FALSE;
    }

    if ((i&1) == 0)
      onTimes[i/2] = (unsigned)(time*1000);
    else
      offTimes[i/2] = (unsigned)(time*1000);
  }

  return SetToneFilterParameters(line, tone, low_freq, high_freq,
                                 numCadences, onTimes, offTimes);
}


BOOL OpalLineInterfaceDevice::SetToneFilterParameters(unsigned /*line*/,
                                                      CallProgressTones /*tone*/,
                                                      unsigned /*lowFrequency*/,
                                                      unsigned /*highFrequency*/,
                                                      PINDEX /*numCadences*/,
                                                      const unsigned * /*onTimes*/,
                                                      const unsigned * /*offTimes*/)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::PlayTone(unsigned, CallProgressTones)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::IsTonePlaying(unsigned)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::StopTone(unsigned)
{
  return FALSE;
}


BOOL OpalLineInterfaceDevice::PlayAudio(unsigned /*line*/, const PString & /*filename*/)
{
  PTRACE(3, "LID\tBase Class PlayAudio method called, exiting with FALSE");
  return FALSE;
}


BOOL OpalLineInterfaceDevice::StopAudio(unsigned /*line*/)
{
  PTRACE(3, "LID\tBase Class StopAudio method called, exiting with FALSE");
  return FALSE;
}
	

OpalLineInterfaceDevice::CallProgressTones
                OpalLineInterfaceDevice::DialOut(unsigned line,
                                                 const PString & number,
                                                 BOOL requireTone)
{
  PTRACE(3, "LID\tDialOut to " << number);

  if (IsLineTerminal(line))
    return NoTone;

  if (!SetLineOffHook(line))
    return NoTone;

  // Should get dial tone within 2 seconds of going off hook
  if (!WaitForTone(line, DialTone, 2000)) {
    if (requireTone)
      return DialTone;
  }

  // Dial the string
  PINDEX lastPos = 0;
  PINDEX nextPos;
  while ((nextPos = number.FindOneOf("!@,")) != P_MAX_INDEX) {
    PlayDTMF(line, number(lastPos, nextPos-1));
    lastPos = nextPos+1;
    switch (number[nextPos]) {
      case '!' :
        if (!HookFlash(line))
          return NoTone;
        break;

      case '@' :
        if (!WaitForTone(line, DialTone, 3000)) {
          if (requireTone)
            return DialTone;
        }
        break;

      case ',' :
        PThread::Current()->Sleep(2000);
        break;
    }
  }

  PlayDTMF(line, number.Mid(lastPos));

  // Wait for busy or ring back
  unsigned tones;
  while ((tones = WaitForToneDetect(line, 5000)) != NoTone) {
    if (tones & BusyTone)
      return BusyTone;
    else if (tones & RingTone)
      break;
  }

  if (requireTone)
    return NoTone;

  return RingTone;
}

static struct {
  const char * isoName;
  unsigned dialCode;
  OpalLineInterfaceDevice::T35CountryCodes t35Code;
  const char * fullName;
  const char * dialTone;
  const char * ringTone;
  const char * busyTone;
} CountryInfo[] = {
  { "AF", 93,   OpalLineInterfaceDevice::Afghanistan,           "Afghanistan" },
  { "AL", 355,  OpalLineInterfaceDevice::Albania,               "Albania" },
  { "DZ", 213,  OpalLineInterfaceDevice::Algeria,               "Algeria" },
  { "AS", 684,  OpalLineInterfaceDevice::AmericanSamoa,         "American Samoa" },
  { "AO", 244,  OpalLineInterfaceDevice::Angola,                "Angola" },
  { "AI", 1264, OpalLineInterfaceDevice::Anguilla,              "Anguilla" },
  { "AG", 1268, OpalLineInterfaceDevice::AntiguaAndBarbuda,     "Antigua and Barbuda" },
  { "AR", 54,   OpalLineInterfaceDevice::Argentina,             "Argentina" },
  { "AC", 247,  OpalLineInterfaceDevice::Ascension,             "Ascension Island" },
  { "AU", 61,   OpalLineInterfaceDevice::Australia,             "Australia",            "425:0.1", "425:0.4-0.2-0.4-2", "425:0.375-0.375" },
  { "AT", 43,   OpalLineInterfaceDevice::Austria,               "Austria" },
  { "BS", 1242, OpalLineInterfaceDevice::Bahamas,               "Bahamas" },
  { "BH", 973,  OpalLineInterfaceDevice::Bahrain,               "Bahrain" },
  { "BD", 880,  OpalLineInterfaceDevice::Bangladesh,            "Bangladesh" },
  { "BB", 1246, OpalLineInterfaceDevice::Barbados,              "Barbados" },
  { "BE", 32,   OpalLineInterfaceDevice::Belgium,               "Belgium" },
  { "BZ", 501,  OpalLineInterfaceDevice::Belize,                "Belize" },
  { "BJ", 229,  OpalLineInterfaceDevice::Benin,                 "Benin" },
  { "BM", 1441, OpalLineInterfaceDevice::Bermudas,              "Bermudas" },
  { "BT", 975,  OpalLineInterfaceDevice::Bhutan,                "Bhutan" },
  { "BO", 591,  OpalLineInterfaceDevice::Bolivia,               "Bolivia" },
  { "BW", 267,  OpalLineInterfaceDevice::Botswana,              "Botswana" },
  { "BR", 55,   OpalLineInterfaceDevice::Brazil,                "Brazil" },
  { "xx", 0,    OpalLineInterfaceDevice::BritishAntarcticTerritory, "British Antarctic Territory" },
  { "IO", 246,  OpalLineInterfaceDevice::BritishIndianOceanTerritory, "British IndianOcean Territory" },
  { "VG", 1284, OpalLineInterfaceDevice::BritishVirginIslands,  "British Virgin Islands" },
  { "BN", 673,  OpalLineInterfaceDevice::BruneiDarussalam,      "Brunei Darussalam" },
  { "BG", 359,  OpalLineInterfaceDevice::Bulgaria,              "Bulgaria" },
  { "BF", 226,  OpalLineInterfaceDevice::BurkinaFaso,           "Burkina Faso" },
  { "BI", 257,  OpalLineInterfaceDevice::Burundi,               "Burundi" },
  { "xx", 0,    OpalLineInterfaceDevice::Byelorussia,           "Byelorussia" },
  { "KH", 855,  OpalLineInterfaceDevice::Cambodia,              "Cambodia" },
  { "CM", 237,  OpalLineInterfaceDevice::Cameroon,              "Cameroon" },
  { "CA", 1,    OpalLineInterfaceDevice::Canada,                "Canada" },
  { "CV", 238,  OpalLineInterfaceDevice::CapeVerde,             "Cape Verde" },
  { "KY", 1345, OpalLineInterfaceDevice::CaymanIslands,         "Cayman Islands" },
  { "CF", 236,  OpalLineInterfaceDevice::CentralAfricanRepublic,"Central African Republic" },
  { "TD", 235,  OpalLineInterfaceDevice::Chad,                  "Chad" },
  { "CL", 56,   OpalLineInterfaceDevice::Chile,                 "Chile" },
  { "CN", 86,   OpalLineInterfaceDevice::China,                 "China" },
  { "CO", 57,   OpalLineInterfaceDevice::Colombia,              "Colombia" },
  { "KM", 269,  OpalLineInterfaceDevice::Comoros,               "Comoros" },
  { "CG", 242,  OpalLineInterfaceDevice::Congo,                 "Congo" },
  { "CK", 682,  OpalLineInterfaceDevice::CookIslands,           "Cook Islands" },
  { "CR", 506,  OpalLineInterfaceDevice::CostaRica,             "Costa Rica" },
  { "CI", 225,  OpalLineInterfaceDevice::CotedIvoire,           "Cote dIvoire" },
  { "CU", 53,   OpalLineInterfaceDevice::Cuba,                  "Cuba" },
  { "CY", 357,  OpalLineInterfaceDevice::Cyprus,                "Cyprus" },
  { "CZ", 420,  OpalLineInterfaceDevice::Czechoslovakia,        "Czech Republic" },
  { "DK", 45,   OpalLineInterfaceDevice::Denmark,               "Denmark" },
  { "DJ", 253,  OpalLineInterfaceDevice::Djibouti,              "Djibouti" },
  { "DM", 1767, OpalLineInterfaceDevice::Dominica,              "Dominica" },
  { "DO", 1809, OpalLineInterfaceDevice::DominicanRepublic,     "Dominican Republic" },
  { "EC", 593,  OpalLineInterfaceDevice::Ecuador,               "Ecuador" },
  { "EG", 20,   OpalLineInterfaceDevice::Egypt,                 "Egypt" },
  { "SV", 503,  OpalLineInterfaceDevice::ElSalvador,            "El Salvador" },
  { "GQ", 240,  OpalLineInterfaceDevice::EquatorialGuinea,      "Equatorial Guinea" },
  { "ET", 251,  OpalLineInterfaceDevice::Ethiopia,              "Ethiopia" },
  { "FK", 500,  OpalLineInterfaceDevice::FalklandIslands,       "Falkland Islands" },
  { "FJ", 679,  OpalLineInterfaceDevice::Fiji,                  "Fiji" },
  { "FI", 358,  OpalLineInterfaceDevice::Finland,               "Finland" },
  { "FR", 33,   OpalLineInterfaceDevice::France,                "France" },
  { "PF", 689,  OpalLineInterfaceDevice::FrenchPolynesia,       "French Polynesia" },
  { "TF", 0,    OpalLineInterfaceDevice::FrenchSouthernAndAntarcticLands, "French Southern and Antarctic Lands" },
  { "GA", 241,  OpalLineInterfaceDevice::Gabon,                 "Gabon" },
  { "GM", 220,  OpalLineInterfaceDevice::Gambia,                "Gambia" },
  { "DE", 49,   OpalLineInterfaceDevice::Germany,               "Germany" },
  { "GH", 233,  OpalLineInterfaceDevice::Ghana,                 "Ghana" },
  { "GI", 350,  OpalLineInterfaceDevice::Gibraltar,             "Gibraltar" },
  { "GR", 30,   OpalLineInterfaceDevice::Greece,                "Greece" },
  { "GD", 1473, OpalLineInterfaceDevice::Grenada,               "Grenada" },
  { "GU", 1671, OpalLineInterfaceDevice::Guam,                  "Guam" },
  { "GT", 502,  OpalLineInterfaceDevice::Guatemala,             "Guatemala" },
  { "GY", 592,  OpalLineInterfaceDevice::Guayana,               "Guayana" },
  { "GG", 441,  OpalLineInterfaceDevice::Guernsey,              "Guernsey" },
  { "GN", 224,  OpalLineInterfaceDevice::Guinea,                "Guinea" },
  { "GW", 245,  OpalLineInterfaceDevice::GuineaBissau,          "Guinea Bissau" },
  { "HT", 509,  OpalLineInterfaceDevice::Haiti,                 "Haiti" },
  { "HN", 504,  OpalLineInterfaceDevice::Honduras,              "Honduras" },
  { "HK", 852,  OpalLineInterfaceDevice::Hongkong,              "Hong Kong" },
  { "HU", 36,   OpalLineInterfaceDevice::Hungary,               "Hungary" },
  { "IS", 354,  OpalLineInterfaceDevice::Iceland,               "Iceland" },
  { "IN", 91,   OpalLineInterfaceDevice::India,                 "India" },
  { "ID", 62,   OpalLineInterfaceDevice::Indonesia,             "Indonesia" },
  { "IR", 98,   OpalLineInterfaceDevice::Iran,                  "Iran" },
  { "IQ", 964,  OpalLineInterfaceDevice::Iraq,                  "Iraq" },
  { "IE", 353,  OpalLineInterfaceDevice::Ireland,               "Ireland" },
  { "IL", 972,  OpalLineInterfaceDevice::Israel,                "Israel" },
  { "IT", 39,   OpalLineInterfaceDevice::Italy,                 "Italy" },
  { "JM", 1876, OpalLineInterfaceDevice::Jamaica,               "Jamaica" },
  { "JP", 81,   OpalLineInterfaceDevice::Japan,                 "Japan" },
  { "JE", 442,  OpalLineInterfaceDevice::Jersey,                "Jersey" },
  { "JO", 962,  OpalLineInterfaceDevice::Jordan,                "Jordan" },
  { "KE", 254,  OpalLineInterfaceDevice::Kenya,                 "Kenya" },
  { "KI", 686,  OpalLineInterfaceDevice::Kiribati,              "Kiribati" },
  { "KR", 82,   OpalLineInterfaceDevice::KoreaRepublic,         "Korea, Republic of" },
  { "KP", 850,  OpalLineInterfaceDevice::DemocraticPeoplesRepublicOfKorea, "Korea, Democratic Peoples Republic of" },
  { "KW", 965,  OpalLineInterfaceDevice::Kuwait,                "Kuwait" },
  { "LA", 856,  OpalLineInterfaceDevice::Lao,                   "Lao" },
  { "LB", 961,  OpalLineInterfaceDevice::Lebanon,               "Lebanon" },
  { "LS", 266,  OpalLineInterfaceDevice::Lesotho,               "Lesotho" },
  { "LR", 231,  OpalLineInterfaceDevice::Liberia,               "Liberia" },
  { "LY", 218,  OpalLineInterfaceDevice::Libya,                 "Libya" },
  { "LI", 423,  OpalLineInterfaceDevice::Liechtenstein,         "Liechtenstein" },
  { "LU", 352,  OpalLineInterfaceDevice::Luxemborg,             "Luxemborg" },
  { "MO", 853,  OpalLineInterfaceDevice::Macao,                 "Macao" },
  { "MG", 261,  OpalLineInterfaceDevice::Madagascar,            "Madagascar" },
  { "MY", 60,   OpalLineInterfaceDevice::Malaysia,              "Malaysia" },
  { "MW", 265,  OpalLineInterfaceDevice::Malawi,                "Malawi" },
  { "MV", 960,  OpalLineInterfaceDevice::Maldives,              "Maldives" },
  { "ML", 223,  OpalLineInterfaceDevice::Mali,                  "Mali" },
  { "MT", 356,  OpalLineInterfaceDevice::Malta,                 "Malta" },
  { "MR", 222,  OpalLineInterfaceDevice::Mauritania,            "Mauritania" },
  { "MU", 230,  OpalLineInterfaceDevice::Mauritius,             "Mauritius" },
  { "MX", 52,   OpalLineInterfaceDevice::Mexico,                "Mexico" },
  { "MC", 377,  OpalLineInterfaceDevice::Monaco,                "Monaco" },
  { "MN", 976,  OpalLineInterfaceDevice::Mongolia,              "Mongolia" },
  { "MS", 1664, OpalLineInterfaceDevice::Montserrat,            "Montserrat" },
  { "MA", 212,  OpalLineInterfaceDevice::Morocco,               "Morocco" },
  { "MZ", 258,  OpalLineInterfaceDevice::Mozambique,            "Mozambique" },
  { "MM", 95,   OpalLineInterfaceDevice::Myanmar,               "Myanmar" },
  { "NR", 674,  OpalLineInterfaceDevice::Nauru,                 "Nauru" },
  { "NP", 977,  OpalLineInterfaceDevice::Nepal,                 "Nepal" },
  { "NL", 31,   OpalLineInterfaceDevice::Netherlands,           "Netherlands",          "425:0.1", "425:1.0-4.0", "425:0.5-0.5" },
  { "AN", 599,  OpalLineInterfaceDevice::NetherlandsAntilles,   "Netherlands Antilles" },
  { "NC", 687,  OpalLineInterfaceDevice::NewCaledonia,          "New Caledonia" },
  { "NZ", 64,   OpalLineInterfaceDevice::NewZealand,            "New Zealand" },
  { "NI", 505,  OpalLineInterfaceDevice::Nicaragua,             "Nicaragua" },
  { "NE", 227,  OpalLineInterfaceDevice::Niger,                 "Niger" },
  { "NG", 234,  OpalLineInterfaceDevice::Nigeria,               "Nigeria" },
  { "NO", 47,   OpalLineInterfaceDevice::Norway,                "Norway" },
  { "OM", 968,  OpalLineInterfaceDevice::Oman,                  "Oman" },
  { "PK", 92,   OpalLineInterfaceDevice::Pakistan,              "Pakistan" },
  { "PA", 507,  OpalLineInterfaceDevice::Panama,                "Panama" },
  { "PG", 675,  OpalLineInterfaceDevice::PapuaNewGuinea,        "Papua New Guinea" },
  { "PY", 595,  OpalLineInterfaceDevice::Paraguay,              "Paraguay" },
  { "PE", 51,   OpalLineInterfaceDevice::Peru,                  "Peru" },
  { "PH", 63,   OpalLineInterfaceDevice::Philippines,           "Philippines" },
  { "PL", 48,   OpalLineInterfaceDevice::Poland,                "Poland" },
  { "PT", 351,  OpalLineInterfaceDevice::Portugal,              "Portugal" },
  { "PR", 1787, OpalLineInterfaceDevice::PuertoRico,            "Puerto Rico" },
  { "QA", 974,  OpalLineInterfaceDevice::Qatar,                 "Qatar" },
  { "RO", 40,   OpalLineInterfaceDevice::Romania,               "Romania" },
  { "RU", 7,    OpalLineInterfaceDevice::USSR,                  "Russia" },
  { "RW", 250,  OpalLineInterfaceDevice::Rwanda,                "Rwanda" },
  { "xx", 0,    OpalLineInterfaceDevice::SaintCroix,            "Saint Croix" },
  { "SH", 290,  OpalLineInterfaceDevice::SaintHelenaAndAscension, "Saint Helena and Ascension" },
  { "KN", 1869, OpalLineInterfaceDevice::SaintKittsAndNevis,    "Saint Kitts and Nevis" },
  { "LC", 1758, OpalLineInterfaceDevice::SaintLucia,            "Saint Lucia" },
  { "xx", 0,    OpalLineInterfaceDevice::SaintThomas,           "Saint Thomas" },
  { "VC", 1784, OpalLineInterfaceDevice::SaintVicentAndTheGrenadines, "Saint Vicent and the Grenadines" },
  { "SM", 378,  OpalLineInterfaceDevice::SanMarino,             "San Marino" },
  { "ST", 239,  OpalLineInterfaceDevice::SaoTomeAndPrincipe,    "Sao Tome and Principe" },
  { "SA", 966,  OpalLineInterfaceDevice::SaudiArabia,           "Saudi Arabia" },
  { "SN", 221,  OpalLineInterfaceDevice::Senegal,               "Senegal" },
  { "SC", 248,  OpalLineInterfaceDevice::Seychelles,            "Seychelles" },
  { "SL", 232,  OpalLineInterfaceDevice::SierraLeone,           "Sierra Leone" },
  { "SG", 65,   OpalLineInterfaceDevice::Singapore,             "Singapore",            "425:0.1", "425:0.4-0.2-0.4-2", "425:0.75-0.75"},
  { "SB", 677,  OpalLineInterfaceDevice::SolomonIslands,        "Solomon Islands" },
  { "SO", 252,  OpalLineInterfaceDevice::Somalia,               "Somalia" },
  { "ZA", 27,   OpalLineInterfaceDevice::SouthAfrica,           "South Africa" },
  { "ES", 34,   OpalLineInterfaceDevice::Spain,                 "Spain" },
  { "LK", 94,   OpalLineInterfaceDevice::SriLanka,              "Sri Lanka" },
  { "SD", 249,  OpalLineInterfaceDevice::Sudan,                 "Sudan" },
  { "SR", 597,  OpalLineInterfaceDevice::Suriname,              "Suriname" },
  { "SZ", 268,  OpalLineInterfaceDevice::Swaziland,             "Swaziland" },
  { "SE", 46,   OpalLineInterfaceDevice::Sweden,                "Sweden" },
  { "CH", 41,   OpalLineInterfaceDevice::Switzerland,           "Switzerland" },
  { "SY", 963,  OpalLineInterfaceDevice::Syria,                 "Syria" },
  { "TZ", 255,  OpalLineInterfaceDevice::Tanzania,              "Tanzania" },
  { "TH", 66,   OpalLineInterfaceDevice::Thailand,              "Thailand" },
  { "TG", 228,  OpalLineInterfaceDevice::Togo,                  "Togo" },
  { "TO", 676,  OpalLineInterfaceDevice::Tonga,                 "Tonga" },
  { "TT", 1868, OpalLineInterfaceDevice::TrinidadAndTobago,     "Trinidad and Tobago" },
  { "TN", 216,  OpalLineInterfaceDevice::Tunisia,               "Tunisia" },
  { "TR", 90,   OpalLineInterfaceDevice::Turkey,                "Turkey" },
  { "TC", 1649, OpalLineInterfaceDevice::TurksAndCaicosIslands, "Turks and Caicos Islands" },
  { "TV", 688,  OpalLineInterfaceDevice::Tuvalu,                "Tuvalu" },
  { "UG", 256,  OpalLineInterfaceDevice::Uganda,                "Uganda" },
  { "UA", 380,  OpalLineInterfaceDevice::Ukraine,               "Ukraine" },
  { "AE", 971,  OpalLineInterfaceDevice::UnitedArabEmirates,    "United Arab Emirates" },
  { "GB", 44,   OpalLineInterfaceDevice::UnitedKingdom,         "United Kingdom",       "350-440:0.1", "400-450:0.4-0.2-0.4-2", "400:0.375-0.375" },
  { "US", 1,    OpalLineInterfaceDevice::UnitedStates,          "United States",        "350-440:0.1", "440-480:2.0-4.0",       "480-620:0.5-0.5" },
  { "UY", 598,  OpalLineInterfaceDevice::Uruguay,               "Uruguay" },
  { "VU", 678,  OpalLineInterfaceDevice::Vanuatu,               "Vanuatu" },
  { "VA", 379,  OpalLineInterfaceDevice::VaticanCityState,      "Vatican City State" },
  { "VE", 58,   OpalLineInterfaceDevice::Venezuela,             "Venezuela" },
  { "VN", 84,   OpalLineInterfaceDevice::VietNam,               "Viet Nam" },
  { "WF", 681,  OpalLineInterfaceDevice::WallisAndFutuna,       "Wallis and Futuna" },
  { "WS", 685,  OpalLineInterfaceDevice::WesternSamoa,          "Western Samoa" },
  { "YE", 967,  OpalLineInterfaceDevice::Yemen,                 "Yemen" },
  { "YU", 381,  OpalLineInterfaceDevice::Yugoslavia,            "Yugoslavia" },
  { "xx", 0,    OpalLineInterfaceDevice::Zaire,                 "Zaire" },
  { "ZM", 260,  OpalLineInterfaceDevice::Zambia,                "Zambia" },
  { "ZW", 263,  OpalLineInterfaceDevice::Zimbabwe,              "Zimbabwe" }
};

OpalLineInterfaceDevice::T35CountryCodes OpalLineInterfaceDevice::GetCountryCode(const PString & str)
{
  for (PINDEX i = 0; i < PARRAYSIZE(CountryInfo); i++)
    if (str *= CountryInfo[i].fullName)
      return CountryInfo[i].t35Code;

  return OpalLineInterfaceDevice::UnknownCountry;
}


PString OpalLineInterfaceDevice::GetCountryCodeName(T35CountryCodes c) 
{
  for (PINDEX i = 0; i < PARRAYSIZE(CountryInfo); i++)
    if (CountryInfo[i].t35Code == c)
      return CountryInfo[i].fullName;

  return "<Unknown>";
}


PString OpalLineInterfaceDevice::GetCountryCodeName() const
{ 
  return GetCountryCodeName(countryCode);
}


BOOL OpalLineInterfaceDevice::SetCountryCode(T35CountryCodes country)
{
  countryCode = country;

  unsigned line;
  for (line = 0; line < GetLineCount(); line++)
    SetToneFilter(line, CNGTone, "1100:0.25");

  for (PINDEX i = 0; i < PARRAYSIZE(CountryInfo); i++) {
    if (CountryInfo[i].t35Code == country) {
      PTRACE(2, "LID\tCountry set to " << CountryInfo[i].fullName);
      for (line = 0; line < GetLineCount(); line++) {
        if (CountryInfo[i].dialTone != NULL)
          SetToneFilter(line, DialTone, CountryInfo[i].dialTone);
        if (CountryInfo[i].ringTone != NULL)
          SetToneFilter(line, RingTone, CountryInfo[i].ringTone);
        if (CountryInfo[i].busyTone != NULL)
          SetToneFilter(line, BusyTone, CountryInfo[i].busyTone);
      }
      return TRUE;
    }
  }

  PTRACE(2, "LID\tCountry set to " << GetCountryCodeName());
  return TRUE;
}


PStringList OpalLineInterfaceDevice::GetCountryCodeNameList() const
{
  PStringList list;
  list.AppendString("United States");
  return list;
}


static PCaselessString DeSpaced(const PString & orig)
{
  PString str = orig.Trim();

  PINDEX space = 0;
  while ((space = str.Find(' ')) != P_MAX_INDEX)
    str.Delete(space, 1);

  return str;
}


BOOL OpalLineInterfaceDevice::SetCountryCodeName(const PString & countryName)
{
  PTRACE(4, "IXJ\tSetting country code name to " << countryName);
  PCaselessString spacelessAndCaseless = DeSpaced(countryName);
  if (spacelessAndCaseless.IsEmpty())
    return FALSE;

  if (isdigit(spacelessAndCaseless[0]))
    return SetCountryCode((T35CountryCodes)spacelessAndCaseless.AsUnsigned());

  PINDEX i;
  if (spacelessAndCaseless[0] == '+') {
    unsigned code = spacelessAndCaseless.AsUnsigned();
    for (i = 0; i < PARRAYSIZE(CountryInfo); i++)
      if (code == CountryInfo[i].dialCode)
        return SetCountryCode(CountryInfo[i].t35Code);
  }
  else if (spacelessAndCaseless.GetLength() == 2) {
    for (i = 0; i < PARRAYSIZE(CountryInfo); i++)
      if (spacelessAndCaseless == CountryInfo[i].isoName)
        return SetCountryCode(CountryInfo[i].t35Code);
  }
  else {
    for (i = 0; i < PARRAYSIZE(CountryInfo); i++)
      if (spacelessAndCaseless == DeSpaced(CountryInfo[i].fullName))
        return SetCountryCode(CountryInfo[i].t35Code);
  }

  SetCountryCode(UnknownCountry);
  return FALSE;
}


PString OpalLineInterfaceDevice::GetErrorText() const
{
  return PChannel::GetErrorText(PChannel::Miscellaneous, osError);
}


void OpalLineInterfaceDevice::PrintOn(ostream & strm) const
{
  strm << GetName();
}


/////////////////////////////////////////////////////////////////////////////

static struct {
  const char * name;

  unsigned bytesPerFrame;
  unsigned rxFramesInPacket;
  unsigned txFramesInPacket;
  BOOL     g7231annexA;

  H245_AudioCapability::Choices capabilitySubtype;

} CodecTypeInfo[] = {
  // Do not alter the order of the next four entries without understanding what
  // H323_LIDCapability::OnReceivedPDU() does with them!
#define G7231A_63_INDEX 1
  { OPAL_G7231A_5k3,   24,   8,  3, TRUE,  H245_AudioCapability::e_g7231 },
  { OPAL_G7231A_6k3,   24,   8,  3, TRUE,  H245_AudioCapability::e_g7231 },
  { OPAL_G7231_5k3,    24,   8,  3, FALSE, H245_AudioCapability::e_g7231 },
  { OPAL_G7231_6k3,    24,   8,  3, FALSE, H245_AudioCapability::e_g7231 },

  { OPAL_G729,         10,  24,  6, FALSE, H245_AudioCapability::e_g729 },
  { OPAL_G729A,        10,  24,  6, FALSE, H245_AudioCapability::e_g729AnnexA },
  { OPAL_G729B,        10,  24,  6, FALSE, H245_AudioCapability::e_g729wAnnexB },
  { OPAL_G729AB,       10,  24,  6, FALSE, H245_AudioCapability::e_g729AnnexAwAnnexB },
  { OPAL_GSM0610,      33,   7,  4, FALSE, H245_AudioCapability::e_gsmFullRate },
  { OPAL_G728,          5,  96, 20, FALSE, H245_AudioCapability::e_g728 },
  { OPAL_G711_ULAW_64K, 8, 240, 30, FALSE, H245_AudioCapability::e_g711Ulaw64k },
  { OPAL_G711_ALAW_64K, 8, 240, 30, FALSE, H245_AudioCapability::e_g711Alaw64k },
};

#define DEFINE_LID_CAPABILITY(cls, capName, fmtName) \
class cls : public H323_LIDCapability { \
  public: \
    cls() : H323_LIDCapability(fmtName) { } \
}; \
H323_REGISTER_CAPABILITY(cls, capName) \

DEFINE_LID_CAPABILITY(H323_LID_G711_ALaw_Capability,  OPAL_G711_ALAW_64K"{hw}",    OpalG711ALaw)
DEFINE_LID_CAPABILITY(H323_LID_G711_uLaw_Capability,  OPAL_G711_ULAW_64K"{hw}",    OpalG711uLaw)
DEFINE_LID_CAPABILITY(H323_LID_G728_Capability,       OPAL_G728"{hw}",             OpalG728)
DEFINE_LID_CAPABILITY(H323_LID_GSM0610_Capability,    OPAL_GSM0610"{hw}",          OpalGSM0610)
DEFINE_LID_CAPABILITY(H323_LID_G729_Capability,       OPAL_G729"{hw}",             OpalG729)
DEFINE_LID_CAPABILITY(H323_LID_G729A_Capability,      OPAL_G729A"{hw}",            OpalG729A)
DEFINE_LID_CAPABILITY(H323_LID_G729B_Capability,      OPAL_G729B"{hw}",            OpalG729B)
DEFINE_LID_CAPABILITY(H323_LID_G729AB_Capability,     OPAL_G729AB"{hw}",           OpalG729AB)
DEFINE_LID_CAPABILITY(H323_LID_G7231_6k3_Capability,  OPAL_G7231_6k3"{hw}",        OpalG7231_6k3)
DEFINE_LID_CAPABILITY(H323_LID_G7231_5k3_Capability,  OPAL_G7231_5k3"{hw}",        OpalG7231_5k3)
DEFINE_LID_CAPABILITY(H323_LID_G7231A_6k3_Capability, OPAL_G7231A_6k3"{hw}",       OpalG7231A_6k3)
DEFINE_LID_CAPABILITY(H323_LID_G7231A_5k3_Capability, OPAL_G7231A_5k3"{hw}",       OpalG7231A_5k3)

#define G7231_CISCO OPAL_G7231A_6k3"-Cisco{hw}"
H323_REGISTER_CAPABILITY(H323_CiscoG7231aLIDCapability, G7231_CISCO)

/////////////////////////////////////////////////////////////////////////////

OpalLineChannel::OpalLineChannel(OpalLineInterfaceDevice & dev,
                                 unsigned line,
                                 const H323AudioCodec & codec)
  : device(dev)
{
  lineNumber = line;
  reading = codec.GetDirection() == H323Codec::Encoder;
  OpalMediaFormat mediaFormat = OpalPCM16;

  if (PIsDescendant(&codec, H323_LIDCodec)) {
    OpalMediaFormat::List mediaFormats = device.GetMediaFormats();
    for (PINDEX i = 0; i < mediaFormats.GetSize(); i++) {
      if (mediaFormats[i] == codec.GetMediaFormat())
        mediaFormat = codec.GetMediaFormat();
    }
  }

  if (reading) {
    if (!device.SetReadFormat(lineNumber, mediaFormat))
      return;
    useDeblocking = mediaFormat.GetFrameSize() != device.GetReadFrameSize(lineNumber);
  }
  else {
    if (!device.SetWriteFormat(lineNumber, mediaFormat))
      return;
    useDeblocking = mediaFormat.GetFrameSize() != device.GetWriteFrameSize(lineNumber);
  }

  PTRACE(3, "LID\tCodec set to " << mediaFormat << ", frame size: rd="
         << device.GetReadFrameSize(lineNumber) << " wr="
         << device.GetWriteFrameSize(lineNumber) << ", "
         << (useDeblocking ? "needs" : "no") << " reblocking.");
  os_handle = 1;
}


OpalLineChannel::~OpalLineChannel()
{
  Close();
}


PString OpalLineChannel::GetName() const
{
  return device.GetName() + psprintf("-%u", lineNumber);
}


BOOL OpalLineChannel::Close()
{
  if (!IsOpen())
    return FALSE;

  os_handle = -1;

  if (reading)
    return device.StopReadCodec(lineNumber);
  else
    return device.StopWriteCodec(lineNumber);
}


BOOL OpalLineChannel::Read(void * buffer, PINDEX length)
{
  lastReadCount = 0;

  if (!reading)
    return SetErrorValues(Miscellaneous, EINVAL, LastReadError);

  if (useDeblocking) {
    device.SetReadFrameSize(lineNumber, length);
    if (device.ReadBlock(lineNumber, buffer, length)) {
      lastReadCount = length;
      return TRUE;
    }
  }
  else {
    if (device.ReadFrame(lineNumber, buffer, lastReadCount))
      return TRUE;
  }

  int osError = device.GetErrorNumber();
  PTRACE_IF(1, osError != 0, "LID\tDevice read frame error: " << device.GetErrorText());

  return SetErrorValues(Miscellaneous, osError, LastReadError);
}


BOOL OpalLineChannel::Write(const void * buffer, PINDEX length)
{
  lastWriteCount = 0;

  if (reading)
    return SetErrorValues(Miscellaneous, EINVAL, LastWriteError);

  if (useDeblocking) {
    device.SetWriteFrameSize(lineNumber, length);
    if (device.WriteBlock(lineNumber, buffer, length)) {
      lastWriteCount = length;
      return TRUE;
    }
  }
  else {
    if (device.WriteFrame(lineNumber, buffer, length, lastWriteCount))
      return TRUE;
  }

  int osError = device.GetErrorNumber();
  PTRACE_IF(1, osError != 0, "LID\tDevice write frame error: " << device.GetErrorText());

  return SetErrorValues(Miscellaneous, osError, LastWriteError);
}


///////////////////////////////////////////////////////////////////////////////

void H323_LIDCapability::AddAllCapabilities(const OpalLineInterfaceDevice & device,
                                            H323Capabilities & capabilities,
                                            PINDEX descriptorNum,
                                            PINDEX simultaneous)
{
  OpalMediaFormat::List codecsAvailable = device.GetMediaFormats();
  for (PINDEX c = 0; c < codecsAvailable.GetSize(); c++) {
    H323_LIDCapability * cap = new H323_LIDCapability(codecsAvailable[c]);
    if (cap->IsValid() && !capabilities.FindCapability(*cap))
      capabilities.SetCapability(descriptorNum, simultaneous, cap);
    else
      delete cap;
    if (codecsAvailable[c] == OpalG7231A_6k3)
      capabilities.SetCapability(descriptorNum, simultaneous,
                                 new H323_CiscoG7231aLIDCapability);
  }
}


H323_LIDCapability::H323_LIDCapability(const OpalMediaFormat & fmt)
  : H323AudioCapability(0, 0),
    mediaFormat(fmt)
{
  codecTableIndex = 0;

  while (IsValid()) {
    if (mediaFormat == CodecTypeInfo[codecTableIndex].name) {
      rxFramesInPacket = CodecTypeInfo[codecTableIndex].rxFramesInPacket;
      txFramesInPacket = CodecTypeInfo[codecTableIndex].txFramesInPacket;
      break;
    }

    codecTableIndex++;
  }
}


BOOL H323_LIDCapability::IsValid() const
{
  return codecTableIndex < PARRAYSIZE(CodecTypeInfo);
}


PObject::Comparison H323_LIDCapability::Compare(const PObject & obj) const
{
  if (!PIsDescendant(&obj, H323_LIDCapability))
    return LessThan;

  Comparison result = H323AudioCapability::Compare(obj);
  if (result != EqualTo)
    return result;

  PINDEX otherIndex = ((const H323_LIDCapability &)obj).codecTableIndex;
  if (CodecTypeInfo[codecTableIndex].g7231annexA < CodecTypeInfo[otherIndex].g7231annexA)
    return LessThan;
  if (CodecTypeInfo[codecTableIndex].g7231annexA > CodecTypeInfo[otherIndex].g7231annexA)
    return GreaterThan;
  return EqualTo;
}


PObject * H323_LIDCapability::Clone() const
{
  return new H323_LIDCapability(*this);
}


PString H323_LIDCapability::GetFormatName() const
{
  return mediaFormat + "{hw}";
}


unsigned H323_LIDCapability::GetSubType() const
{
  return CodecTypeInfo[codecTableIndex].capabilitySubtype;
}


H323Codec * H323_LIDCapability::CreateCodec(H323Codec::Direction direction) const
{
  return new H323_LIDCodec(mediaFormat,
                           direction,
                           direction == H323Codec::Encoder ? txFramesInPacket : rxFramesInPacket,
                           codecTableIndex);
}


BOOL H323_LIDCapability::OnSendingPDU(H245_AudioCapability & pdu,
                                      unsigned packetSize) const
{
  pdu.SetTag(GetSubType());

  switch (pdu.GetTag()) {
    case H245_AudioCapability::e_gsmFullRate :
    {
      H245_GSMAudioCapability & gsm = pdu;
      gsm.m_audioUnitSize = packetSize*33;
      break;
    }
    case H245_AudioCapability::e_g7231 :
    {
      H245_AudioCapability_g7231 & g7231 = pdu;
      g7231.m_maxAl_sduAudioFrames = packetSize;
      g7231.m_silenceSuppression = CodecTypeInfo[codecTableIndex].g7231annexA;
      break;
    }
    default :
    {
      PASN_Integer & value = pdu;
      value = packetSize;
    }
  }

  return TRUE;
}


BOOL H323_LIDCapability::OnReceivedPDU(const H245_AudioCapability & pdu,
                                       unsigned & packetSize)
{
  if (pdu.GetTag() != GetSubType())
    return FALSE;

  switch (pdu.GetTag()) {
    case H245_AudioCapability::e_gsmFullRate :
    {
      const H245_GSMAudioCapability & gsm = pdu;
      packetSize = gsm.m_audioUnitSize/33;
      break;
    }
    case H245_AudioCapability::e_g7231 :
    {
      const H245_AudioCapability_g7231 & g7231 = pdu;
      packetSize = g7231.m_maxAl_sduAudioFrames;

      BOOL g7231annexA = g7231.m_silenceSuppression;
      if (g7231annexA != CodecTypeInfo[codecTableIndex].g7231annexA) {
        // Move to the other G.723.1 version
        codecTableIndex += (g7231annexA ? -2 : 2);
        mediaFormat = CodecTypeInfo[codecTableIndex].name;
      }
      break;
    }
    default :
    {
      const PASN_Integer & value = pdu;
      packetSize = value;
    }
  }

  return TRUE;
}


/////////////////////////////////////////////////////////////////////////////

H323_CiscoG7231aLIDCapability::H323_CiscoG7231aLIDCapability()
  : H323NonStandardAudioCapability(1, 1, 181, 0, 18, (const BYTE*)"G7231ar", 7)
{
}


PObject * H323_CiscoG7231aLIDCapability::Clone() const
{
  return new H323_CiscoG7231aLIDCapability(*this);
}


PString H323_CiscoG7231aLIDCapability::GetFormatName() const
{
  return G7231_CISCO;
}


H323Codec * H323_CiscoG7231aLIDCapability::CreateCodec(H323Codec::Direction direction) const
{
  return new H323_LIDCodec(OpalG7231A_6k3, direction, 1, G7231A_63_INDEX);
}


/////////////////////////////////////////////////////////////////////////////

H323_LIDCodec::H323_LIDCodec(const char * fmt,
                             Direction direction,
                             unsigned numFrames,
                             PINDEX index)
  : H323AudioCodec(fmt, direction)
{
  codecTableIndex = index;
  packetSize = CodecTypeInfo[index].bytesPerFrame;

  /* Special case for G.711 encoder, note this helps with optimisation of
    sound data but will break if remote does not send the maximum number of
    bytes that it said it could. It is legal for the remote end to do so
    though no endpoints seem to actually do that.
   */
  if (packetSize == 8) {
    packetSize *= numFrames;
    samplesPerFrame *= numFrames;
  }

  missedCount = 0;
  lastSID[0] = 2;
  lastFrameWasSignal = TRUE;

  PTRACE(3, "LID\tCreated codec: pt=" << mediaFormat.GetPayloadType()
         << ", bytes=" << packetSize << ", samples=" << mediaFormat.GetFrameTime());
}


BOOL H323_LIDCodec::Read(BYTE * buffer, unsigned & length, RTP_DataFrame &)
{
  PWaitAndSignal mutex(rawChannelMutex);

  // This reads to an H323_IxJChannel class
  PINDEX count;
  if (!ReadRaw(buffer, packetSize, count))
    return FALSE;

  // In the case of G.723.1 remember the last SID frame we sent and send
  // it again if the hardware sends us a CNG frame.
  if (mediaFormat.GetPayloadType() == RTP_DataFrame::G7231) {
    switch (count) {
      case 1 : // CNG frame
        memcpy(buffer, lastSID, 4);
        count = 4;
        lastFrameWasSignal = FALSE;
        break;
      case 4 :
        if ((*buffer&3) == 2)
          memcpy(lastSID, buffer, 4);
        lastFrameWasSignal = FALSE;
        break;
      default :
        lastFrameWasSignal = TRUE;
    }
  }

  length = DetectSilence() ? 0 : count;
  return TRUE;
}


BOOL H323_LIDCodec::Write(const BYTE * buffer,
                          unsigned length,
                          const RTP_DataFrame & /*frame*/,
                          unsigned & written)
{
  // This writes to an H323_IxJChannel class
  if (length > packetSize)
    length = packetSize;

  // Check for writing silence
  PBYTEArray silenceBuffer;
  if (length != 0)
    missedCount = 0;
  else {
    switch (mediaFormat.GetPayloadType()) {
      case RTP_DataFrame::G7231 :
        if (missedCount++ < 4) {
          static const BYTE g723_erasure_frame[24] = { 0xff, 0xff, 0xff, 0xff };
          buffer = g723_erasure_frame;
          length = 24;
        }
        else {
          static const BYTE g723_cng_frame[4] = { 3 };
          buffer = g723_cng_frame;
          length = 1;
        }
        break;

      case RTP_DataFrame::PCMU :
      case RTP_DataFrame::PCMA :
        buffer = silenceBuffer.GetPointer(packetSize);
        memset((void *)buffer, 0xff, packetSize);
        length = packetSize;
        break;

      case RTP_DataFrame::G729 :
        if (mediaFormat.Find('B') != P_MAX_INDEX) {
          static const BYTE g729_sid_frame[2] = { 1 };
          buffer = g729_sid_frame;
          length = 2;
          break;
        }
        // Else fall into default case

      default :
        buffer = silenceBuffer.GetPointer(packetSize); // Fills with zeros
        length = packetSize;
        break;
    }
  }

  PWaitAndSignal mutex(rawChannelMutex);

  if (!rawDataChannel->Write(buffer, length))
    return FALSE;

  written = rawDataChannel->GetLastWriteCount();
  return TRUE;
}


BOOL H323_LIDCodec::IsRawDataChannelNative() const
{
  return TRUE;
}


BOOL H323_LIDCodec::DetectSilence()
{
  // Can never have silence if NoSilenceDetection
  if (silenceDetectMode == NoSilenceDetection)
    return FALSE;

  if (!CodecTypeInfo[codecTableIndex].g7231annexA)
    return H323AudioCodec::DetectSilence();

  // Utilise the codecs own silence detection algorithm

  // If no change ie still talking or still silent, resent frame counter
  if (inTalkBurst == lastFrameWasSignal)
    framesReceived = 0;
  else {
    framesReceived++;
    // If have had enough consecutive frames talking/silent, swap modes.
    if (framesReceived >= (inTalkBurst ? silenceDeadbandFrames : signalDeadbandFrames)) {
      inTalkBurst = !inTalkBurst;
      PTRACE(4, "Codec\tSilence detection transition: "
             << (inTalkBurst ? "Talk" : "Silent"));
    }
  }

  return !inTalkBurst;
}


unsigned H323_LIDCodec::GetAverageSignalLevel()
{
  PWaitAndSignal mutex(rawChannelMutex);

  return ((OpalLineChannel*)rawDataChannel)->GetDevice().GetAverageSignalLevel(0, direction == Decoder);
}


/////////////////////////////////////////////////////////////////////////////
