/*
 * vblasterlid.cxx
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
 * $Log: vblasterlid.cxx,v $
 * Revision 1.12  2005/11/14 23:25:22  csoutheren
 * Removed obsolete constructs that cause compiler warnings in new compilers
 *
 * Revision 1.11  2005/06/07 07:59:11  csoutheren
 * Applied patch 1176459 for PocketPC. Thanks to Matthias Weber
 *
 * Revision 1.10  2004/07/11 11:26:33  rjongbloed
 * Fixed error in Voice Blaster tone queue, thanks German Garcia
 *
 * Revision 1.9  2003/12/03 06:58:00  csoutheren
 * More vblaster implementation
 *
 * Revision 1.8  2003/11/10 12:38:20  csoutheren
 * Additional fixes for Fobbit Windows driver
 *
 * Revision 1.7  2002/09/03 06:25:00  robertj
 * Cosmetic change to formatting.
 *
 * Revision 1.6  2002/08/05 10:03:48  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.5  2002/07/09 00:39:08  robertj
 * Patches for latest fobbit driver, thanks Jian Yang
 *
 * Revision 1.4  2002/02/05 06:19:47  craigs
 * Changed to use OPAL define rather than strings
 *
 * Revision 1.3  2002/01/15 07:23:10  craigs
 * Added IsDevicePresent command
 *
 * Revision 1.2  2002/01/15 05:54:16  robertj
 * Added bad implementation for GetDeviceNames()
 *
 * Revision 1.1  2002/01/15 04:16:52  craigs
 * Initial version
 *
 */

#include <ptlib.h>

#ifdef __GNUC__
#pragma implementation "vblasterlid.h"
#endif

#include "vblasterlid.h"

#define   STARTUP_TIMEOUT   500
/*

  This code uses the VoIPBlaster interface as written by Dave Fobbitt (http://www.fobbit.com).
  All of the information about the VoIPBlaster command set and functions was derived directly
  from the code made available by Dave. This code requires Dave's USB drivers to be installed 
  as per the instructions on his site. Thanks to Dave for making this code available for
  general use.

  Introduction

  The interface to the VoIPBlaster (VB) is implemented using two pairs of read/write channels. These
  are implemented as four named pipes for Windows, or two sockets for Unix. One channel is used
  for sending commands to the VB and reading status, and the other channel is used for sending and
  receiving audio data.

  Initialisation:
    TBD
    
  Commands:
    There are 27 different comands recognised by the VB. Each command is one byte.

        COMMAND_PHONE_OFF  0x01     drop loop current
        COMMAND_PHONE_ON   0x02     used on startup
        COMMAND_RING_ON    0x03     start ringing
        COMMAND_RING_OFF   0x04     used on startup & to stop ringing
        COMMAND_VOUT_START 0x05     start audio output
        COMMAND_VOUT_STOP  0x06     stop audio output
        COMMAND_VINP_START 0x07     start audio input
        COMMAND_VINP_STOP  0x08     stop audio input
        COMMAND_UNKNOWN_1  0x09     Unknown (TESTSTART)
        COMMAND_UNKNOWN_2  0x0a     Unknown (TESTSTOP)
        COMMAND_UNKNOWN_3  0x0b     Unknown (SENDFAXTONE)
        COMMAND_0x0c       0x0c     Go offhook for headset
        COMMAND_0x0d       0x0d     Go onhook for headset
        COMMAND_SETUP_MODE 0x0e     Unknown(goto setup mode)
        COMMAND_VOUT_DONE  0x0f     voice in/out off, report output drained
        COMMAND_0x10       0x10     Unknown (used in file output, seems ok without)
        COMMAND_0x11       0x11     Unknown (used in file output, seems ok without)
        COMMAND_MUTE_ON    0x12     Audio mute on
        COMMAND_MUTE_OFF   0x13     Audio mute off
        COMMAND_VOL_0      0x34     Set volume (min)
        COMMAND_VOL_1      0x35     Set volume
        COMMAND_VOL_2      0x36     Set volume
        COMMAND_VOL_3      0x37     Set volume (default)
        COMMAND_VOL_4      0x38     Set volume
        COMMAND_VOL_5      0x39     Set volume
        COMMAND_VOL_6      0x3a     Set volume (max)

  Status:
    There are 11 different status responses sent by the VB. Each status is one byte.
        STATUS_NONE        0x00     No status
        STATUS_HOOK_OFF    0x01     Offhook
        STATUS_HOOK_ON     0x02     Onhook
        STATUS_DEBUG       0x00     Not used (DEBUG)
        STATUS_RINGDETECT  0x00     Not used (RINGDETECT)
        STATUS_RINGING_ON  0x05     Ring started 
        STATUS_RINGING_OFF 0x06     Ring stopped
        STATUS_HEADSET_IN  0x08     Headset plugged in
        STATUS_HEADSET_OUT 0x09     Headset unplugged
        STATUS_0x0a        0x0a     Unknown (setup accepted?)
        STATUS_VOUT_DONE   0x0c     Voice output done

  Voice:
    The VB will accept audio in G.723.1 format at either 6.4kbps frames (24 bytes) or 5.3 kbps
    frames (20 bytes). However, it only generates audio data at 5.3 kbps frames (20 bytes)

*/

static BYTE blasterInit1[] =
{
    0x3b,0x00,0x40,0x8b // first 2 bytes is length, second 2 bytes is command?
};

static BYTE blasterInit2[] =
{
    0x00,0x01,0x00,0x00,0x18,0x02,0x8f,0x00,
    0x10,0x00,0x28,0x40,0x03,0x1a,0x0d,0x0c,
    0xfa,0x43,0xfd,0xea,0x93,0xfe,0x1a,0x41,
    0x00,0x4a,0x93,0xfe,0x2a,0x40,0x00,0x1a,
    0x93,0xfe,0x3a,0x0a,0x00,0x1f,0x3c,0x00,
    0x8c,0x0d,0x03,0xa3,0x23,0xa2,0xdf,0x0d,
    0x0c,0x3a,0x40,0x00,0x2a,0x93,0xfe,0x4a,
    0x0a,0x00,0x0f
};

// this gets sent each time the voice output goes idle
static BYTE blasterInit3[] =
{
    0x75,0x58,0x9b,0x04,0x72,0x00,0x00,0x11,
    0xe0,0x00,0x65,0x82,0x00,0x90,0x00,0x1c,
    0x96,0xc1,0x0f,0xf2,0x3d,0x95,0x8e,0x5e,
    0xe7,0x66,0xef,0xd4,0xba,0x21,0x0d,0x30,
    0xcb,0x1e,0x52,0x35,0x9a,0xb6,0xff,0x7f,
    0x74,0x58,0x9b,0x04,0x68,0x08,0x00,0x99,
    0x52,0xfa,0x75,0xd7,0x72,0xba,0xdb,0x03,
    0x3d,0xdb,0x77,0xd0,0x77,0x03,0x1f,0x05
};

// some silence data, for now only used in 'vblast_ring' to kill the dialtone
static BYTE silence[] =
{
    0xd5,0x14,0x0a,0x0d,0x1a,0x00,0x00,0x0a,
    0x80,0x00,0xaf,0x06,0x00,0x00,0xfc,0x24,
    0x9b,0x70,0xcf,0xc0,0xa1,0x53,0x18,0x00,
    0x08,0x04,0xfe,0x50,0x8f,0x12,0x50,0x50,
    0x4b,0x32,0x56,0x77,0x15,0xe9,0x0f,0xe8,
    0xd5,0xc8,0xad,0x68,0xc8,0x74,0xe4,0x27,
    0x71,0xd8,0x87,0x34,0xad,0x60,0x07,0xa8,
    0xb6,0x64,0x0f,0x44,0x59,0x02,0xf4,0x00,
    0x0e,0x80,0xba,0x68,0x73,0x00,0xe0,0xdf,
    0x82,0xf4,0xa3,0x1f,0x18,0xb3,0x70,0x2e,
    0xdd,0x1c,0xb1,0x00,0x02,0xfc,0x07,0xde,
    0x09,0xc2,0x5e,0x82,0xaf,0xbc,0x5a,0x6c,
    0xa2,0x02,0xbb,0xac,0x65,0x47,0x99,0x74,
    0xfe,0xf4,0xe5,0xf7,0x70,0x90,0xe7,0x21,
    0x15,0x33,0x56,0x8a,0x77,0x50,0xb5,0x42,
    0x51,0x17,0xf2,0x4c,0xa8,0xfc,0x10,0x60,
    0x82,0x1e,0x50,0x2f,0xa4,0x57,0x31,0x1e,
    0xdd,0xc0,0xaf,0x6f,0x4d,0x1f,0xf5,0x08,
    0x18,0x90,0x15,0x7f,0x70,0x1e,0x60,0x3e,
    0x15,0xfb,0xa0,0x0d,0xbd,0x60,0x90,0x6d,
    0x65,0x43,0xb1,0xdc,0xc2,0xd5,0x19,0xe5,
    0xe1,0xe8,0x27,0xe4,0xcf,0x82,0x39,0xec,
    0x38,0x84,0x3b,0x75,0x51,0x3b,0xb1,0x70,
    0xde,0x68,0xba,0x06,0x79,0x0f,0x76,0x18,
    0x74,0x53,0x45,0x4f,0x83,0x52,0xa0,0xa0,
    0x5d,0xc1,0xed,0xc4,0x9f,0x77,0x27,0x36,
    0x83,0xf9,0x07,0x7f,0x28,0xf3,0x41,0x41,
    0x85,0x94,0x15,0xc0,0x45,0x13,0xee,0x30,
    0x54,0x8c,0xea,0x37,0x03,0xf8,0xae,0x1f,
    0x85,0xe7,0xed,0x21,0x58,0x01,0xff,0xe5,
    0x75,0xc3,0x09,0x05,0x12,0x00,0x26,0xa7,
    0x0b,0x26,0x9f,0x81,0x26,0x50,0x06,0x97,
    0x31,0xa4,0x3c,0xca,0x1d,0x97,0xc2,0x9d,
    0x42,0x6d,0xcf,0xae,0xe6,0xe5,0x27,0x04,
    0x03,0xc2,0x93,0x5d,0xa7,0x62,0xf1,0x87,
    0x5d,0x41,0xe5,0x0a,0x0a,0x70,0x69,0x3f,
    0xf1,0xf4,0xfe,0x0d,0x4e,0x27,0x97,0x5b,
    0xb0,0x0b,0xe5,0x78,0xa5,0x26,0x09,0x49,
    0x90,0xfc,0xf1,0x77,0x52,0x0c,0xdf,0xef,
    0x7f,0x8d,0x84,0x15,0x48,0xc7,0xff,0x5b,
};

/////////////////////////////////////////////////////////////////////////////

OpalVoipBlasterDevice::OpalVoipBlasterDevice()
  : dtmfQueue(DTMFQueueSize)
{
  statusThread = NULL;
}

OpalVoipBlasterDevice::~OpalVoipBlasterDevice()
{
  Close();
}

BOOL OpalVoipBlasterDevice::Open(const PString & device)
{
  Close();

  int deviceIndex = device.AsInteger();

  readStopped = writeStopped = TRUE;

  // open the lowlevel device
  if (!vBlaster.OpenCommand(deviceIndex)) {
    PTRACE(3, "vBlaster\tCould not open VoipBlaster device \"" << device << '"');
    return FALSE;
  }
  if (!vBlaster.OpenData()) {
    PTRACE(3, "vBlaster\tCould not open VoipBlaster data for device \"" << device << '"');
    return FALSE;
  }

  // put device into setup mode
  PTRACE(3, "vBlaster\tSending setup command");

  // put the handset on hook, which should stop all voice data
  vBlaster.WriteCommand(VoipBlasterInterface::Command_HS_ONHOOK); 

  // flush all input
  vBlaster.Flush(STARTUP_TIMEOUT);

  vBlaster.WriteCommand(VoipBlasterInterface::Command_SETUP_MODE); 

  // setup for incoming status
  hookState = FALSE;
  headset   = FALSE;
  ringOn    = TRUE;     // so we can detect ring off
  firstTime = FALSE;


  //vBlaster.Flush(STARTUP_TIMEOUT);

  vBlaster.WriteData(blasterInit1, sizeof(blasterInit1));

  //vBlaster.Flush(STARTUP_TIMEOUT);

  vBlaster.WriteData(blasterInit2, sizeof(blasterInit2));

  //vBlaster.Flush(STARTUP_TIMEOUT);

  int status = VoipBlasterInterface::Status_Empty;

  int i;
  for (i = 3; ringOn && i > 0; i--) {

    vBlaster.WriteCommand(VoipBlasterInterface::Command_VOL_3);
    vBlaster.WriteCommand(VoipBlasterInterface::Command_RING_OFF);
    vBlaster.WriteCommand(VoipBlasterInterface::Command_PHONE_ON);

    PTimer timer(2000);

    do {
      status = vBlaster.ReadStatus(STARTUP_TIMEOUT);
      if (status != VoipBlasterInterface::Status_Empty)
        HandleStatus(status);
    } while (ringOn && timer.IsRunning());
  }

  if (i == 0) {
    PTRACE(3, "vBlaster\tCould not initialise");
    return FALSE;
  }

  // set up thread to read status pipe
  statusRunning = TRUE;
  statusThread = PThread::Create(PCREATE_NOTIFIER(StatusHandler), 0,
                                 PThread::NoAutoDeleteThread,
                                 PThread::NormalPriority,
                                 "VbStatus:%x");

  // unmute output and set default value
  vBlaster.WriteCommand(VoipBlasterInterface::Command_VOL_3);
  vBlaster.WriteCommand(VoipBlasterInterface::Command_MUTE_OFF);
  vBlaster.WriteCommand(VoipBlasterInterface::Command_VOUT_STOP);
  vBlaster.WriteCommand(VoipBlasterInterface::Command_VINP_STOP);

  // save the device name
  deviceName = device;
  PTRACE(3, "vBlaster\tVoipBlaster device \"" << device << "\" opened");
  os_handle = deviceIndex;

  return TRUE;
}


BOOL OpalVoipBlasterDevice::Close()
{
  PWaitAndSignal m(vbMutex);

  if (!IsOpen())
    return FALSE;

  // flag the status thread to stop running on next status byte
  statusRunning = FALSE;

  // send a command to the phone stat will force a status byte to return
  vBlaster.WriteCommand(VoipBlasterInterface::Command_PHONE_OFF);
  vBlaster.WriteCommand(VoipBlasterInterface::Command_MUTE_OFF);

  vBlaster.WriteCommand(VoipBlasterInterface::Command_VOUT_DONE);
  vBlaster.WriteData   (blasterInit3, sizeof(blasterInit3));

  // close the device - this will stop the status thread for sure!
  vBlaster.CloseCommand();

  // wait for the status thread to terminate
  statusThread->WaitForTermination();
  delete statusThread;
  statusThread = NULL;

  deviceName = PString();

  os_handle = -1;
  return TRUE;
}


PString OpalVoipBlasterDevice::GetName() const
{
  return deviceName;
}

void OpalVoipBlasterDevice::StatusHandler(PThread &, INT)
{
  while (statusRunning) {
    int status = vBlaster.ReadStatus();
    if (status != VoipBlasterInterface::Status_Empty)
      HandleStatus(status);
  }
}

void OpalVoipBlasterDevice::HandleStatus(int status)
{
  switch (status) {
    //case VoipBlasterInterface::Status_NONE:        // No status
    //  break;

    case VoipBlasterInterface::Status_HOOK_OFF:    // Offhook
      PTRACE(1, "VB\tHook off");
      hookState = TRUE;
      headset   = FALSE;
      break;

    case VoipBlasterInterface::Status_HOOK_ON:     // Onhook
      PTRACE(1, "VB\tHook on");
      hookState = FALSE;
      headset   = FALSE;
      break;

    case VoipBlasterInterface::Status_RINGING_ON:  // Ring started 
      PTRACE(1, "VB\tRing start");
      ringOn = TRUE;
      break;

    case VoipBlasterInterface::Status_RINGING_OFF: // Ring stopped
      PTRACE(1, "VB\tRing end");
      ringOn = FALSE;
      break;

    case VoipBlasterInterface::Status_HEADSET_IN:  // Headset plugged in
      PTRACE(1, "VB\tHeadset in");
      headset = TRUE;
      break;

    case VoipBlasterInterface::Status_HEADSET_OUT: // Headset unplugged
      PTRACE(1, "VB\tHeadset out");
      headset = FALSE;
      break;

    case VoipBlasterInterface::Status_0x0a:        // Unknown (setup accepted?)
      PTRACE(1, "VB\tStatus 0xa");

      // read 17 byte serial number
      BYTE serialNumber[17];
      memset(serialNumber, 0, sizeof(serialNumber));
      vBlaster.ReadData(serialNumber, sizeof(serialNumber), STARTUP_TIMEOUT);
      {
        PString str;
        for (int i = 0; i < sizeof(serialNumber); i++)
          str.sprintf("%02x ", serialNumber[i]);
        PTRACE(3, "vBlaster\tFirst time serial number " << str);
      }
      firstTime = TRUE;
      break;

    case VoipBlasterInterface::Status_VOUT_DONE:   // Voice output done
      PTRACE(1, "VB\tVOUT done");
      break;

    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case '*':
    case '#':
      PTRACE(1, "VB\tDTMF digit " << (char )status);
      dtmfQueue.Enqueue((BYTE)status);
      break;

    default:
      PTRACE(1, "VB\tUnknown status value " << status);
  }
}


BOOL OpalVoipBlasterDevice::IsLineOffHook(unsigned line)
{
  PWaitAndSignal m(vbMutex);

  if (!IsOpen())
    return FALSE;

  if (line > 0)
    return FALSE;

  return hookState;
}


BOOL OpalVoipBlasterDevice::SetLineOffHook(unsigned /*line*/, BOOL /* newState*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::HasHookFlash(unsigned /* line */)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::IsLineRinging(unsigned /*line*/, DWORD * /*cadence*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::RingLine(unsigned line, DWORD cadence)
{
  PWaitAndSignal m(vbMutex);

  if (!IsOpen())
    return FALSE;

  if (line > 0)
    return FALSE;

  // %%%%%% this really needs to use a timer to implement cadences.
  if (cadence == 0)
    vBlaster.WriteCommand(VoipBlasterInterface::Command_RING_OFF);
  else
    vBlaster.WriteCommand(VoipBlasterInterface::Command_RING_ON); 

  return TRUE;
}


BOOL OpalVoipBlasterDevice::IsLineDisconnected(unsigned /*line*/, BOOL /*checkForWink*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::SetLineToLineDirect(unsigned /*line1 */, unsigned /*line2*/, BOOL /*connect*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::IsLineToLineDirect(unsigned /*line1*/, unsigned /*line2*/)
{
  return FALSE;
}


static const struct {
  const char * mediaFormat;
  PINDEX frameSize;
} CodecInfo[] = {
  { OPAL_G7231_6k3,  24 },
  { OPAL_G7231_5k3,  20 },
};


OpalMediaFormat::List OpalVoipBlasterDevice::GetMediaFormats() const
{
  OpalMediaFormat::List codecs;

  codecs.Append(new OpalMediaFormat(CodecInfo[0].mediaFormat));

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


BOOL OpalVoipBlasterDevice::SetReadFormat(unsigned line, const OpalMediaFormat & mediaFormat)
{
  StopReadCodec(line);

  PWaitAndSignal m(vbMutex);
  PWaitAndSignal mutex(readMutex);

  readCodecType = FindCodec(mediaFormat);
  if (readCodecType == P_MAX_INDEX) {
    PTRACE(1, "vBlaster\tUnsupported read codec requested: " << mediaFormat);
    return FALSE;
  }

  if (!writeStopped && readCodecType != writeCodecType) {
    PTRACE(1, "vBlaster\tAsymmetric codecs requested: "
              "read=" << CodecInfo[readCodecType].mediaFormat
           << " write=" << CodecInfo[writeCodecType].mediaFormat);
    return FALSE;
  }

  PTRACE(3, "vBlaster\tSetReadFormat(" << CodecInfo[readCodecType].mediaFormat << ')');

  readFrameSize = CodecInfo[readCodecType].frameSize;

  if (writeStopped)
    vBlaster.OpenData();

  vBlaster.WriteCommand(VoipBlasterInterface::Command_VINP_START);

  readDelay.Restart();

  readStopped = FALSE;

  return TRUE;
}


BOOL OpalVoipBlasterDevice::SetWriteFormat(unsigned line, const OpalMediaFormat & mediaFormat)
{
  StopWriteCodec(line);

  PWaitAndSignal m(vbMutex);
  PWaitAndSignal mutex(writeMutex);

  writeCodecType = FindCodec(mediaFormat);
  if (writeCodecType == P_MAX_INDEX) {
    PTRACE(1, "vBlaster\tUnsupported write codec requested: " << mediaFormat);
    return FALSE;
  }

  if (!readStopped && writeCodecType != readCodecType) {
    PTRACE(1, "vBlaster\tAsymmetric codecs requested: "
              "read=" << CodecInfo[readCodecType].mediaFormat
           << " write=" << CodecInfo[writeCodecType].mediaFormat);
    return FALSE;
  }

  PTRACE(3, "vBlaster\tSetWriteFormat(" << CodecInfo[writeCodecType].mediaFormat << ')');

  writeFrameSize = CodecInfo[writeCodecType].frameSize;

  if (readStopped)
    vBlaster.OpenData();

  vBlaster.WriteCommand(VoipBlasterInterface::Command_VOUT_START);
  vBlaster.WriteCommand(VoipBlasterInterface::Command_VOL_3);
  vBlaster.WriteCommand(VoipBlasterInterface::Command_MUTE_OFF);

  writeDelay.Restart();

  writeStopped = FALSE;
  return TRUE;
}


OpalMediaFormat OpalVoipBlasterDevice::GetReadFormat(unsigned)
{
  if (readCodecType == P_MAX_INDEX)
    return "";
  return CodecInfo[readCodecType].mediaFormat;
}


OpalMediaFormat OpalVoipBlasterDevice::GetWriteFormat(unsigned)
{
  if (writeCodecType == P_MAX_INDEX)
    return "";
  return CodecInfo[writeCodecType].mediaFormat;
}


BOOL OpalVoipBlasterDevice::SetRawCodec(unsigned)
{
  return FALSE;
}

BOOL OpalVoipBlasterDevice::StopReadCodec(unsigned line)
{
  PTRACE(3, "vBlaster\tStopping read codec");

  PWaitAndSignal m(vbMutex);
  readMutex.Wait();
  if (!readStopped) {
    readStopped = TRUE;
    vBlaster.WriteCommand(VoipBlasterInterface::Command_VINP_STOP);
  }

  if (writeStopped)
    vBlaster.CloseData();

  readMutex.Signal();

  return OpalLineInterfaceDevice::StopReadCodec(line);
}


BOOL OpalVoipBlasterDevice::StopWriteCodec(unsigned line)
{
  PTRACE(3, "vBlaster\tStopping write codec");

  PWaitAndSignal m(vbMutex);
  writeMutex.Wait();
  if (!writeStopped) {
    writeStopped = TRUE;
    vBlaster.WriteCommand(VoipBlasterInterface::Command_VOUT_STOP);
  }

  if (readStopped)
    vBlaster.CloseData();

  writeMutex.Signal();

  return OpalLineInterfaceDevice::StopWriteCodec(line);
}


BOOL OpalVoipBlasterDevice::StopRawCodec(unsigned /*line*/)
{
  return FALSE;
}


PINDEX OpalVoipBlasterDevice::GetReadFrameSize(unsigned)
{
  return readFrameSize;
}


BOOL OpalVoipBlasterDevice::SetReadFrameSize(unsigned, PINDEX size)
{
  readFrameSize = size;
  return TRUE;
}


PINDEX OpalVoipBlasterDevice::GetWriteFrameSize(unsigned)
{
  return writeFrameSize;
}


BOOL OpalVoipBlasterDevice::SetWriteFrameSize(unsigned, PINDEX size)
{
  writeFrameSize = size;
  return TRUE;
}


BOOL OpalVoipBlasterDevice::ReadFrame(unsigned, void * buffer, PINDEX & wasRead)
{
  PWaitAndSignal mutex(readMutex);
  if (readStopped)
    return FALSE;

  readDelay.Delay(30);

  if (!hookState)
    return FALSE;

  int stat;
  if ((stat = vBlaster.ReadData(buffer, 20)) != 20) {
    PTRACE(1, "Error reading frame - " << stat);
    return FALSE;
  }

  wasRead = 20;

  return TRUE;
}


BOOL OpalVoipBlasterDevice::WriteFrame(unsigned, const void * buffer, PINDEX /*count*/, PINDEX & written)
{
  PWaitAndSignal m(writeMutex);
  if (writeStopped)
    return FALSE;

  writeDelay.Delay(30);

  const BYTE * p = (const BYTE *)buffer;

  PINDEX toWrite = 0;
  switch (*p & 3) {
    case 0:
      toWrite = 24;
      vBlaster.WriteData(buffer, 24);
      break;
    case 1:
      toWrite = 20;
      vBlaster.WriteData(buffer, 20);
      break;
    case 2:
      toWrite = 4;
      break;
    default:
      // Check for frame erasure command
      if (memcmp(buffer, "\xff\xff\xff\xff", 4) == 0)
        toWrite = 24;
      else
        toWrite = 1;
      break;
  }

  written = toWrite;

  return TRUE;
}


unsigned OpalVoipBlasterDevice::GetAverageSignalLevel(unsigned, BOOL /*playback*/)
{
  return UINT_MAX;
}


BOOL OpalVoipBlasterDevice::EnableAudio(unsigned /*line*/, BOOL /*enable*/)
{
  return TRUE;
}


BOOL OpalVoipBlasterDevice::SetRecordVolume(unsigned /*line*/, unsigned /*volume*/)
{
  return TRUE;
}


BOOL OpalVoipBlasterDevice::SetPlayVolume(unsigned /*line*/, unsigned /*volume*/)
{
  return TRUE;
}


BOOL OpalVoipBlasterDevice::GetRecordVolume(unsigned, unsigned & /*volume*/)
{
  return TRUE;
}


BOOL OpalVoipBlasterDevice::GetPlayVolume(unsigned, unsigned & volume)
{
  volume = 50;
  return TRUE;
}


OpalLineInterfaceDevice::AECLevels OpalVoipBlasterDevice::GetAEC(unsigned)
{
  return AECOff;
}


BOOL OpalVoipBlasterDevice::SetAEC(unsigned, AECLevels /*level*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::GetVAD(unsigned)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::SetVAD(unsigned, BOOL /*enable*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::GetCallerID(unsigned, PString & /*idString*/, BOOL /*full*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::SetCallerID(unsigned, const PString & /*idString*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::SendCallerIDOnCallWaiting(unsigned, const PString & /*idString*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::SendVisualMessageWaitingIndicator(unsigned /*line*/, BOOL /*isOn*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::PlayDTMF(unsigned /*line*/,
                                     const char * digits,
                             DWORD /*onTime*/, DWORD /*offTime*/)
{
  PINDEX i;
  for (i = 0; digits[i] != '\0'; i++) {
    PWaitAndSignal m(vbMutex);
    vBlaster.WriteCommand((VoipBlasterInterface::Command)digits[i]);
  }

  return TRUE;
}


char OpalVoipBlasterDevice::ReadDTMF(unsigned)
{
  int v = dtmfQueue.Dequeue();
  return (v < 0) ? (char)0 : (char)v;
}


BOOL OpalVoipBlasterDevice::GetRemoveDTMF(unsigned)
{
  return TRUE;
}


BOOL OpalVoipBlasterDevice::SetRemoveDTMF(unsigned, BOOL /*state*/)
{
  return TRUE;
}


unsigned OpalVoipBlasterDevice::IsToneDetected(unsigned /*line*/)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::PlayTone(unsigned /*line*/, CallProgressTones /*tone*/)
{
  return FALSE;
}

BOOL OpalVoipBlasterDevice::IsTonePlaying(unsigned)
{
  return FALSE;
}


BOOL OpalVoipBlasterDevice::StopTone(unsigned)
{
  return FALSE;
}


DWORD OpalVoipBlasterDevice::GetSerialNumber()
{
  return 0;
}


PStringArray OpalVoipBlasterDevice::GetDeviceNames()
{
  PStringArray array;

  VoipBlasterInterface blaster;
  PINDEX i = 0;
  while ((i < 16) && blaster.IsDevicePresent(i)) {
    array[i] = i;
    i++;
  }

  return array;
}

BOOL OpalVoipBlasterDevice::SetCountryCode(T35CountryCodes /*country*/)
{
  return TRUE;
}


/////////////////////////////////////////////////////////////////////////////

OpalVoipBlasterDevice::ByteQueue::ByteQueue(PINDEX _qMax)
  : qMax(_qMax)
{
  qOut = qLen = 0;
  queue.SetSize(qMax);
}

int OpalVoipBlasterDevice::ByteQueue::Dequeue()
{
  PWaitAndSignal m(mutex);
  if (qLen == 0)
    return -1;

  int v = queue[qOut];

  ++qOut;
  qOut = (qOut % qMax);
  qLen--;

  return v;
}

BOOL OpalVoipBlasterDevice::ByteQueue::Enqueue(BYTE v)
{
  PWaitAndSignal m(mutex);

  if (qLen == qMax)
    return FALSE;

  queue[(qOut + qLen) % qMax] = v;
  qLen++;

  return TRUE;
}


/////////////////////////////////////////////////////////////////////////////

#ifdef _WIN32

#include <initguid.h>
#include <setupapi.h>

#ifndef _WIN32_WINCE
#pragma comment(lib, "setupapi.lib")
#endif

// {00873FDF-61A8-11d1-AA5E-00C04FB1728B}  for VB_USB.SYS

DEFINE_GUID(GUID_CLASS_VOIP_BLASTER,
  0x873fdf, 0x61a8, 0x11d1, 0xaa, 0x5e, 0x0, 0xc0, 0x4f, 0xb1, 0x72, 0x8b);

static BOOL GetDeviceInterfacePath(HDEVINFO hDevInfo,
                                   PSP_DEVICE_INTERFACE_DATA pDeviceInterfaceData,
                                   char *dest, DWORD dwMaxLen)
{
  PSP_INTERFACE_DEVICE_DETAIL_DATA pDetailData     = NULL;
  ULONG                            requiredLength  =    0;

  // allocate a function class device data structure to receive the
  // goods about this particular device.
  SetupDiGetInterfaceDeviceDetail(hDevInfo,
            pDeviceInterfaceData, //
            NULL,            // probing so no output buffer yet
            0,               // probing so output buffer length of zero
            &requiredLength, //
            NULL);           // not interested in the specific dev-node

  pDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)LocalAlloc(LPTR, requiredLength);
  ZeroMemory(pDetailData, requiredLength );
  pDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

  // Retrieve the information from Plug and Play.
  if (!SetupDiGetDeviceInterfaceDetail(hDevInfo,
               pDeviceInterfaceData,
               pDetailData,
               requiredLength,
               NULL,
               NULL)) {
    PTRACE(1, "VB\tError " << GetLastError() << " in GetDeviceInterfacePath");
    LocalFree(pDetailData);
    return FALSE;
  }

  strncpy(dest,pDetailData->DevicePath, dwMaxLen);
  LocalFree(pDetailData);
  return TRUE;
}

static BOOL GetDevicePath( LPGUID pGuid, DWORD dwIndex, char *dest, DWORD dwMaxLen )
{
  
  SP_DEVINFO_DATA DeviceInfoData;
  SP_DEVICE_INTERFACE_DATA DeviceInterfaceData;
  BOOL result;

    // Create a HDEVINFO with all present devices.
  HDEVINFO hDevInfoList = SetupDiGetClassDevs(
        pGuid,  // this guid only
        0,      // Enumerator
        0,
        DIGCF_PRESENT | DIGCF_INTERFACEDEVICE );
    
  if (hDevInfoList == INVALID_HANDLE_VALUE) {
    PTRACE(1, "VB\tError " << GetLastError() << " in GetDevicePath:SetupDiGetClassDevs");
    return FALSE;
  }
    
  // Get the Info for the specific device instance (dwIndex)
  DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
  if (!SetupDiEnumDeviceInfo(hDevInfoList, dwIndex, &DeviceInfoData)) {
    PTRACE(1, "VB\tError " << GetLastError() << " in GetDevicePath:SetupDiEnumDeviceInfo");
    SetupDiDestroyDeviceInfoList(hDevInfoList); // Cleanup
    return FALSE;
  }

  // for the desired interface, get the path
  ZeroMemory(&DeviceInterfaceData, sizeof(DeviceInterfaceData));
  DeviceInterfaceData.cbSize = sizeof(DeviceInterfaceData);
  if(!SetupDiEnumDeviceInterfaces(hDevInfoList, &DeviceInfoData, pGuid, 0, &DeviceInterfaceData)) {
    PTRACE(1, "VB\tError " << GetLastError() << " in GetDevicePath:SetupDiEnumDeviceInterfaces");
    SetupDiDestroyDeviceInfoList(hDevInfoList); // Cleanup
    return FALSE;
  }

  result = GetDeviceInterfacePath( hDevInfoList, &DeviceInterfaceData, dest, dwMaxLen );
    
  SetupDiDestroyDeviceInfoList(hDevInfoList); // Cleanup

  return result;
}

static HANDLE OpenPipe(const PString & filename, DWORD dwIndex)
{
  char completeDeviceName[256] = "";

  if (!GetDevicePath((LPGUID)&GUID_CLASS_VOIP_BLASTER, dwIndex, 
        completeDeviceName, sizeof(completeDeviceName))) {
    return  INVALID_HANDLE_VALUE;
  }

  strcat(completeDeviceName, "\\" );
  strcat(completeDeviceName, filename);

  HANDLE h = CreateFile(completeDeviceName, 
                        GENERIC_WRITE | GENERIC_READ,
                        FILE_SHARE_WRITE | FILE_SHARE_READ, 
                        NULL, 
                        OPEN_EXISTING, 
                        FILE_FLAG_OVERLAPPED, 
                        NULL);

  if (h == INVALID_HANDLE_VALUE) {
    PTRACE(1, "Failed to open " << completeDeviceName << " : " << GetLastError());
  }

  return h;
}


/////////////////////////////////////////////////////////////////////////////

VoipBlasterInterface::VoipBlasterInterface()
{
  deviceIndex = P_MAX_INDEX;
  PINDEX i;
  for (i = 0; i < NumPipes; i++) 
    pipes[i] = INVALID_HANDLE_VALUE;

}

BOOL VoipBlasterInterface::IsDevicePresent(PINDEX deviceIndex)
{
  char completeDeviceName[256] = "";

  return GetDevicePath((LPGUID)&GUID_CLASS_VOIP_BLASTER, deviceIndex, 
        completeDeviceName, sizeof(completeDeviceName));
}


BOOL VoipBlasterInterface::OpenCommand(PINDEX _deviceIndex)
{
  CloseCommand();

  deviceIndex = _deviceIndex;

  // open the command and status pipes to the driver
  if (!OpenVOIPPipe(CommandPipe)) {
    PTRACE(1, "VB\tOpen of command pipe failed");
    CloseCommand();
    return FALSE;
  }

  if (!OpenVOIPPipe(StatusPipe)) {
    PTRACE(1, "VB\tOpen of status pipe failed");
    CloseCommand();
    return FALSE;
  }

  return TRUE;
}

BOOL VoipBlasterInterface::CloseCommand()
{
  CloseData();

  if (deviceIndex == P_MAX_INDEX)
    return FALSE;

  CloseHandle(pipes[CommandPipe]);
  pipes[CommandPipe] = INVALID_HANDLE_VALUE;

  CloseHandle(pipes[StatusPipe]);
  pipes[StatusPipe] = INVALID_HANDLE_VALUE;

  deviceIndex = P_MAX_INDEX;

  return TRUE;
}


BOOL VoipBlasterInterface::OpenData()
{
  if (deviceIndex == P_MAX_INDEX)
    return FALSE;

  // open the data pipes to the driver
  if (!OpenVOIPPipe(VoiceOutPipe)) {
    PTRACE(1, "VB\tOpen of command pipe failed");
    CloseCommand();
    return FALSE;
  }

  if (!OpenVOIPPipe(VoiceInPipe)) {
    PTRACE(1, "VB\tOpen of status pipe failed");
    CloseCommand();
    return FALSE;
  }

  return TRUE;
}


BOOL VoipBlasterInterface::CloseData()
{
  if (deviceIndex == P_MAX_INDEX)
    return FALSE;

  CloseHandle(pipes[VoiceOutPipe]);
  pipes[VoiceOutPipe] = INVALID_HANDLE_VALUE;

  CloseHandle(pipes[VoiceInPipe]);
  pipes[VoiceInPipe] = INVALID_HANDLE_VALUE;

  return TRUE;
}

BOOL VoipBlasterInterface::OpenVOIPPipe(VoipBlasterInterface::Pipe pipeIndex)
{
  if (deviceIndex == P_MAX_INDEX)
    return FALSE;

  return (pipes[pipeIndex] = OpenPipe(psprintf("PIPE%02i", pipeIndex), deviceIndex)) != INVALID_HANDLE_VALUE;
}


BOOL VoipBlasterInterface::WriteCommand(Command cmd)
{
  BYTE b = (BYTE)cmd;
  return WritePipe(pipes[CommandPipe], &b, 1) == 1;
}

VoipBlasterInterface::Status VoipBlasterInterface::ReadStatus(const PTimeInterval duration)
{
  BYTE b;
  if (ReadPipe(pipes[StatusPipe], &b, 1, duration) == 1)
    return (Status)b;

  return Status_Empty;
}

BOOL VoipBlasterInterface::WriteData(const void * data, PINDEX len)
{
  return WritePipe(pipes[VoiceOutPipe], data, len) == len;
}

int VoipBlasterInterface::ReadData(void * data, PINDEX len, const PTimeInterval duration)
{
  return ReadPipe(pipes[VoiceInPipe], data, len, duration);
}

void VoipBlasterInterface::Flush(const PTimeInterval wait)
{
  BYTE buffer[1000];
  while (ReadData(buffer, 1000, wait) > 0)
    ;

  while (ReadPipe(pipes[StatusPipe], buffer, 1000, wait) > 0)
    ;

#if 0
  BOOL closeOnEnd = (pipes[VoiceInPipe] == INVALID_HANDLE_VALUE);
  if (closeOnEnd && !OpenVOIPPipe(VoiceInPipe)) {
    PTRACE(2, "VB\tCould not open voice in pipe for flush");
    return;
  }

  PTimer closeTimer;
  closeTimer.SetNotifier(PCREATE_NOTIFIER(CloseTimeout));
  closeTimer = wait;
  PINDEX count = 0;
  for (;;) {
    BYTE b;
    if (ReadPipe(pipes[VoiceInPipe], &b, 1) != 1)
      break;
    count++;
    closeTimer.Reset();
  }

  closeTimer.Stop();

  PError << "Flushed " << count << " bytes" << endl;
#endif
}

void VoipBlasterInterface::CloseTimeout(PTimer &, INT)
{
  if (pipes[VoiceInPipe] != INVALID_HANDLE_VALUE) {
    CloseHandle(pipes[VoiceInPipe]);
    pipes[VoiceInPipe] = INVALID_HANDLE_VALUE;
  }
}

int VoipBlasterInterface::WritePipe(HANDLE handle, const void *bp, DWORD len)
{
  DWORD writeCount;
  PWin32Overlapped overlap;

  ResetEvent(overlap.hEvent);

  if (::WriteFile(handle, bp, len, &writeCount, &overlap))
    return writeCount; 

  if (GetLastError() != ERROR_IO_PENDING) {
    PTRACE(1, "VB\tWriteFile to pipe failed");
    return -1;
  }

  if (!GetOverlappedResult(handle, &overlap, &writeCount, TRUE)) {
    PTRACE(1, "VB\tGetOverlappedResult on pipe failed");
    return -1;
  }
  
  return writeCount;
}


int VoipBlasterInterface::ReadPipe(HANDLE handle, void *bp, DWORD len, const PTimeInterval duration)
{
  DWORD readCount;
  PWin32Overlapped overlap;

  ResetEvent(overlap.hEvent);

  if (::ReadFile(handle, bp, len, &readCount, &overlap))
    return readCount;

  if (GetLastError() != ERROR_IO_PENDING) {
    PTRACE(1, "VB\tReadFile from pipe failed");
    return -1;
  }

  DWORD msecs = (duration == PMaxTimeInterval) ? INFINITE : duration.GetInterval();
  if (msecs < 500)
    msecs = 500;

  switch (WaitForSingleObject(overlap.hEvent, msecs)) {
    case WAIT_OBJECT_0:
      // do nothing ; the device is ready
      break;

    case WAIT_TIMEOUT:
      // cancel the I/O operation;
      CancelIo(handle);
      break;

    default:
      PTRACE(1, "VB\tWaitForSingleObject on pipe failed");
      return -1;
  }

  if (!GetOverlappedResult(handle, &overlap, &readCount, TRUE)) {
    PTRACE(1, "VB\tGetOverlappedResult on pipe failed");
    return -1;
  }

  return readCount;
}


#endif // _WIN32


/////////////////////////////////////////////////////////////////////////////
