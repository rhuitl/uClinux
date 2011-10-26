/*
 * h261codec.cxx
 *
 * H.323 protocol handler
 *
 * Open H323 Library
 *
 * Copyright (c) 1998-2000 Equivalence Pty. Ltd.
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
 * Contributor(s): Michele Piccini (michele@piccini.com)
 *                 Derek Smithies (derek@indranet.co.nz)
 *
 * $Log: h261codec.cxx,v $
 * Revision 1.73  2006/06/06 08:05:40  csoutheren
 * Make sure maxBitRate is always initialised to a useful value
 *
 * Revision 1.72  2006/04/19 01:31:46  csoutheren
 * Fix problem with resizing H.261 video
 *
 * Revision 1.71  2006/03/28 05:15:02  csoutheren
 * Change video codecs to set grabber capture size rather than
 * grabber size setting codec size
 *
 * Revision 1.70  2006/03/21 10:43:35  csoutheren
 * Ensure bytes per frame is set when writing to video devices
 *
 * Revision 1.69  2005/11/25 00:10:24  csoutheren
 * Applied patch #1303543 from Hannes Friederich
 * Added guard to weird conditions in H261 codec
 *
 * Revision 1.68  2005/02/24 19:54:18  dsandras
 * Fixed quality problem with H.261 thanks to Hannes Friederich.
 *
 * Revision 1.67  2005/01/21 21:25:42  csoutheren
 * Fixed delete [] operator
 *
 * Revision 1.66  2004/08/26 08:05:04  csoutheren
 * Codecs now appear in abstract factory system
 * Fixed Windows factory bootstrap system (again)
 *
 * Revision 1.65  2004/07/07 08:04:55  csoutheren
 * Added video codecs to default codec list, but H.263 is only loaded if the .so/DLL is found
 *
 * Revision 1.64  2004/05/20 02:07:29  csoutheren
 * Use macro to work around MSVC internal compiler errors
 *
 * Revision 1.63  2004/05/19 07:38:23  csoutheren
 * Changed OpalMediaFormat handling to use abstract factory method functions
 *
 * Revision 1.62  2004/05/04 03:33:33  csoutheren
 * Added guards against comparing certain kinds of Capabilities
 *
 * Revision 1.61  2004/04/03 08:28:06  csoutheren
 * Remove pseudo-RTTI and replaced with real RTTI
 *
 * Revision 1.60  2004/03/24 00:39:12  dereksmithies
 * Changes from Michael Smith for use in reporting frames/second. Many Thanks
 *
 * Revision 1.59  2004/01/02 00:31:42  dereksmithies
 * Fix test on presence/absence of video.
 *
 * Revision 1.58  2003/12/14 10:42:29  rjongbloed
 * Changes for compilability without video support.
 *
 * Revision 1.57  2003/10/02 23:37:56  dereksmithies
 * Add fix for fast update problem in h261 codec. Thanks to Martin André for doing the initial legwork.
 *
 * Revision 1.56  2003/04/03 23:54:15  robertj
 * Added fast update to H.261 codec, thanks Gustavo García Bernardo
 *
 * Revision 1.55  2003/03/20 23:45:46  dereks
 * Make formatting more consistant with the openh323.org standard.
 *
 * Revision 1.54  2003/03/17 08:05:02  robertj
 * Removed videoio classes in openh323 as now has versions in pwlib.
 *
 * Revision 1.53  2003/03/11 22:05:00  dereks
 * Video receive will not terminate in abnormal situations
 * Thanks to Damien Sandras.
 *
 * Revision 1.52  2002/12/29 22:35:34  dereks
 * Fix so video with Windows XP works. Thanks Damien Sandras.
 *
 * Revision 1.51  2002/12/24 07:38:49  robertj
 * Patches to fix divide by zero error, thanks Damien Sandras
 *
 * Revision 1.50  2002/12/16 09:11:19  robertj
 * Added new video bit rate control, thanks Walter H. Whitlock
 *
 * Revision 1.49  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.48  2002/05/19 22:03:45  dereks
 * Add fix from Sean Miceli, so correct P64Decoder is picked in calls with Netmeeting.
 * Many thanks, good work!
 *
 * Revision 1.47  2002/04/26 04:58:34  dereks
 * Add Walter Whitlock's fixes, based on Victor Ivashim's suggestions to improve
 * the quality with Netmeeting. Thanks guys!!!
 *
 * Revision 1.46  2002/04/05 00:53:19  dereks
 * Modify video frame encoding so that frame is encoded on an incremental basis.
 * Thanks to Walter Whitlock - good work.
 *
 * Revision 1.45  2002/01/09 06:07:13  robertj
 * Fixed setting of RTP timestamp values on video transmission.
 *
 * Revision 1.44  2002/01/09 00:21:39  robertj
 * Changes to support outgoing H.245 RequstModeChange.
 *
 * Revision 1.43  2002/01/08 01:30:41  robertj
 * Tidied up some PTRACE debug output.
 *
 * Revision 1.42  2002/01/03 23:05:50  dereks
 * Add methods to count number of H261 packets waiting to be sent.
 *
 * Revision 1.41  2001/12/20 01:19:43  dereks
 * modify ptrace statments.
 *
 * Revision 1.40  2001/12/13 03:01:23  dereks
 * Modify trace statement.
 *
 * Revision 1.39  2001/12/04 05:13:12  robertj
 * Added videa bandwidth limiting code for H.261, thanks Jose Luis Urien.
 *
 * Revision 1.38  2001/12/04 04:26:06  robertj
 * Added code to allow change of video quality in H.261, thanks Damian Sandras
 *
 * Revision 1.37  2001/10/23 02:17:16  dereks
 * Initial release of cu30 video codec.
 *
 * Revision 1.36  2001/09/26 01:59:31  robertj
 * Fixed MSVC warning.
 *
 * Revision 1.35  2001/09/25 03:14:47  dereks
 * Add constant bitrate control for the h261 video codec.
 * Thanks Tiziano Morganti for the code to set bit rate. Good work!
 *
 * Revision 1.34  2001/09/21 02:51:29  robertj
 * Added default session ID to media format description.
 *
 * Revision 1.33  2001/08/22 01:28:20  robertj
 * Resolved confusion with YUV411P and YUV420P video formats, thanks Mark Cooke.
 *
 * Revision 1.32  2001/07/09 07:19:40  rogerh
 * Make the encoder render a frames (for local video) only when there is a
 * renderer attached
 *
 * Revision 1.31  2001/06/19 02:01:42  dereks
 * The video encoder thread ends if the renderframe fails.
 *
 * Revision 1.30  2001/06/13 21:46:37  dereks
 * Add 5 msec separator between consecutive packets generated from the same
 * frame. Prevents lost packets, and improves reliability.
 *
 * Revision 1.29  2001/05/25 01:10:26  dereks
 * Remove unnecessary packet receive variable.
 * Alter the position of the check for change in frame size.
 *
 * Revision 1.28  2001/02/09 05:13:55  craigs
 * Added pragma implementation to (hopefully) reduce the executable image size
 * under Linux
 *
 * Revision 1.27  2001/01/25 07:27:16  robertj
 * Major changes to add more flexible OpalMediaFormat class to normalise
 *   all information about media types, especially codecs.
 *
 * Revision 1.26  2000/12/19 22:33:44  dereks
 * Adjust so that the video channel is used for reading/writing raw video
 * data, which better modularizes the video codec.
 *
 * Revision 1.25  2000/10/13 02:20:32  robertj
 * Fixed capability clone so gets all fields including those in ancestor.
 *
 * Revision 1.24  2000/10/13 01:47:26  dereks
 * Include command option for setting the number of transmitted video
 * frames per second.   use --videotxfps n
 *
 * Revision 1.23  2000/09/08 06:41:38  craigs
 * Added ability to set video device
 * Added ability to select test input frames
 *
 * Revision 1.22  2000/08/28 23:47:41  dereks
 * Fix bug in resizing image of received video
 *
 * Revision 1.21  2000/08/21 04:45:06  dereks
 * Fix dangling pointer that caused segfaults for windows&unix users.
 * Improved the test image which is used when video grabber won't open.
 * Added code to handle setting of video Tx Quality.
 * Added code to set the number of background blocks sent with every frame.
 *
 * Revision 1.20  2000/07/13 12:31:31  robertj
 * Fixed format name output for in band switching H.261
 *
 * Revision 1.19  2000/07/04 13:00:36  craigs
 * Fixed problem with selecting large and small video sizes
 *
 * Revision 1.18  2000/06/10 09:21:36  rogerh
 * Make GetFormatName return H.261 QCIF or H.261 CIF
 *
 * Revision 1.17  2000/05/10 04:05:34  robertj
 * Changed capabilities so has a function to get name of codec, instead of relying on PrintOn.
 *
 * Revision 1.16  2000/05/02 04:32:26  robertj
 * Fixed copyright notice comment.
 *
 * Revision 1.15  2000/04/29 03:01:48  robertj
 * Fixed bug in receive of H261 capability, setting cif & qcif variables correctly.
 *
 * Revision 1.14  2000/03/24 01:23:49  robertj
 * Directory reorganisation.
 *
 * Revision 1.13  2000/03/21 03:06:49  robertj
 * Changes to make RTP TX of exact numbers of frames in some codecs.
 *
 * Revision 1.12  2000/02/10 03:08:02  craigs
 * Added ability to specify NTSC or PAL video format
 *
 * Revision 1.11  2000/02/04 05:11:19  craigs
 * Updated for new Makefiles and for new video transmission code
 *
 * Revision 1.10  2000/01/13 04:03:45  robertj
 * Added video transmission
 *
 * Revision 1.9  1999/12/23 23:02:35  robertj
 * File reorganision for separating RTP from H.323 and creation of LID for VPB support.
 *
 * Revision 1.8  1999/11/29 08:20:47  craigs
 * Updated for new codec interface
 *
 * Revision 1.7  1999/11/01 00:52:00  robertj
 * Fixed various problems in video, especially ability to pass error return value.
 *
 * Revision 1.6  1999/10/08 09:59:03  robertj
 * Rewrite of capability for sending multiple audio frames
 *
 * Revision 1.5  1999/10/08 04:58:38  robertj
 * Added capability for sending multiple audio frames in single RTP packet
 *
 * Revision 1.4  1999/09/21 14:13:53  robertj
 * Windows MSVC compatibility.
 *
 * Revision 1.3  1999/09/21 08:10:03  craigs
 * Added support for video devices and H261 codec
 *
 * Revision 1.2  1999/09/18 13:24:38  craigs
 * Added ability to disable jitter buffer
 * Added ability to access entire RTP packet in codec Write
 *
 * Revision 1.1  1999/09/08 04:05:49  robertj
 * Added support for video capabilities & codec, still needs the actual codec itself!
 *
 */

#include <ptlib.h>

#ifdef __GNUC__
#pragma implementation "h261codec.h"
#endif

#include "h261codec.h"

#ifndef NO_H323_VIDEO

#include "h245.h"
#include "rtp.h"

#include "vic/p64.h"
#include "vic/p64encoder.h"

#define new PNEW
#define INC_ENCODE 1

char OpalH261[] = "H.261";

namespace PWLibStupidLinkerHacks {
  int h261Loader;
};

OPAL_MEDIA_FORMAT_DECLARE(OpalH261Format,
        OpalH261,
        OpalMediaFormat::DefaultVideoSessionID,
        RTP_DataFrame::H261,
        FALSE,  // No jitter for video
        240000, // bits/sec
        2000,   // Not sure of this value!
        0,      // No intrinsic time per frame
        OpalMediaFormat::VideoTimeUnits,
        0)

H323_H261Capability::H323_H261Capability(unsigned _qcifMPI,
                                         unsigned _cifMPI,
                                         BOOL _temporalSpatialTradeOffCapability,
                                         BOOL _stillImageTransmission,
                                         unsigned _maxBitRate)
{
  qcifMPI = _qcifMPI;
  cifMPI = _cifMPI;
  temporalSpatialTradeOffCapability = _temporalSpatialTradeOffCapability;
  maxBitRate = _maxBitRate;
  stillImageTransmission = _stillImageTransmission;
}


PObject * H323_H261Capability::Clone() const
{
  return new H323_H261Capability(*this);
}


PObject::Comparison H323_H261Capability::Compare(const PObject & obj) const
{
  if (!PIsDescendant(&obj, H323_H261Capability))
    return LessThan;

  Comparison result = H323Capability::Compare(obj);
  if (result != EqualTo)
    return result;

  const H323_H261Capability & other = (const H323_H261Capability &)obj;

  if (((qcifMPI > 0) && (other.qcifMPI > 0)) ||
      ((cifMPI  > 0) && (other.cifMPI > 0)))
    return EqualTo;

  if (qcifMPI > 0)
    return LessThan;

  return GreaterThan;
}


PString H323_H261Capability::GetFormatName() const
{
  if (qcifMPI > 0 && cifMPI > 0)
    return "H.261-(Q)CIF";

  if (qcifMPI > 0)
    return "H.261-QCIF";

  if (cifMPI > 0)
    return "H.261-CIF";

  return "H.261";
}


unsigned H323_H261Capability::GetSubType() const
{
  return H245_VideoCapability::e_h261VideoCapability;
}




BOOL H323_H261Capability::OnSendingPDU(H245_VideoCapability & cap) const
{
  cap.SetTag(H245_VideoCapability::e_h261VideoCapability);

  H245_H261VideoCapability & h261 = cap;
  if (qcifMPI > 0) {
    h261.IncludeOptionalField(H245_H261VideoCapability::e_qcifMPI);
    h261.m_qcifMPI = qcifMPI;
  }
  if (cifMPI > 0) {
    h261.IncludeOptionalField(H245_H261VideoCapability::e_cifMPI);
    h261.m_cifMPI = cifMPI;
  }
  h261.m_temporalSpatialTradeOffCapability = temporalSpatialTradeOffCapability;
  h261.m_maxBitRate = (maxBitRate == 0) ? 3270 : maxBitRate;
  h261.m_stillImageTransmission = stillImageTransmission;
  return TRUE;
}


BOOL H323_H261Capability::OnSendingPDU(H245_VideoMode & pdu) const
{
  pdu.SetTag(H245_VideoMode::e_h261VideoMode);
  H245_H261VideoMode & mode = pdu;
  mode.m_resolution.SetTag(cifMPI > 0 ? H245_H261VideoMode_resolution::e_cif
                                      : H245_H261VideoMode_resolution::e_qcif);
  mode.m_bitRate = (maxBitRate == 0) ? 3270 : maxBitRate;
  mode.m_stillImageTransmission = stillImageTransmission;
  return TRUE;
}


BOOL H323_H261Capability::OnReceivedPDU(const H245_VideoCapability & cap)
{
  if (cap.GetTag() != H245_VideoCapability::e_h261VideoCapability)
    return FALSE;

  const H245_H261VideoCapability & h261 = cap;
  if (h261.HasOptionalField(H245_H261VideoCapability::e_qcifMPI))
    qcifMPI = h261.m_qcifMPI;
  else
    qcifMPI = 0;
  if (h261.HasOptionalField(H245_H261VideoCapability::e_cifMPI))
    cifMPI = h261.m_cifMPI;
  else
    cifMPI = 0;
  temporalSpatialTradeOffCapability = h261.m_temporalSpatialTradeOffCapability;
  maxBitRate = h261.m_maxBitRate;
  stillImageTransmission = h261.m_stillImageTransmission;
  return TRUE;
}


H323Codec * H323_H261Capability::CreateCodec(H323Codec::Direction direction) const
{
  return new H323_H261Codec(direction, qcifMPI > 0);
}


//////////////////////////////////////////////////////////////////////////////

H323_H261Codec::H323_H261Codec(Direction dir, BOOL _isqCIF)
  : H323VideoCodec("H.261", dir), isqCIF(_isqCIF)
{
  PTRACE(3, "H261\t" << (isqCIF ? "Q" : "") << "CIF "
         << (dir == Encoder ? "en" : "de") << "coder created.");

  // no video decoder until we receive a packet
  videoDecoder = NULL;

  // no video encoder until we receive a packet
  videoEncoder = NULL;


  // other stuff
  now = 1;
  rvts = NULL;
  nblk = ndblk = 0;
  doFastUpdate = FALSE;

  // initial size of the window is CIF
  if (dir == Encoder) {
    frameWidth  = isqCIF ? QCIF_WIDTH  : CIF_WIDTH;
    frameHeight = isqCIF ? QCIF_HEIGHT : CIF_HEIGHT;
  } else {
    frameWidth=0;
    frameHeight=0;
  }

  frameNum = 0; // frame counter
  timestampDelta = 0;
  videoBitRateControlModes = None;

  // video quality control
  videoQMin = 1;
  videoQMax = 24;
  videoQuality = 9; // default = 9
  //SetTxQualityLevel( videoQuality ); // don't have encoder yet

  // video bit rate control
  sumFrameTimeMs = 0;
  sumAdjFrameTimeMs = 0;
  sumFrameBytes = 0;
  bitRateHighLimit = 0;
  videoBitRateControlModes = None;
  targetFrameTimeMs = 167;
  oldTime = newTime = 0;
}


H323_H261Codec::~H323_H261Codec()
{
  PWaitAndSignal mutex1(videoHandlerActive);

  if (videoDecoder)
  {
    delete videoDecoder;
    videoDecoder = NULL;
  }

  if (videoEncoder){
    delete videoEncoder;
    videoEncoder = NULL;
  }

  if (rvts){
    delete rvts;
  }
}


//This function grabs, displays, and compresses a video frame into
//into H261 packets.
//Get another frame if all packets of previous frame have been sent.
//Get next packet on list and send that one.
//Render the current frame if all of its packets have been sent.
BOOL H323_H261Codec::Read(BYTE * buffer,
                          unsigned & length,
                          RTP_DataFrame & frame)
{
  fastUpdateMutex.Wait();
  if ((videoEncoder != NULL) && doFastUpdate)
    videoEncoder->FastUpdatePicture();
  fastUpdateMutex.Signal();

  PWaitAndSignal mutex1(videoHandlerActive);
  PTRACE(6,"H261\tAcquire next packet from h261 encoder.\n");

  if ( videoEncoder == NULL ) {
    videoEncoder = new P64Encoder(videoQuality, fillLevel);
    videoEncoder->SetSize(frameWidth, frameHeight);
  }

  if( rawDataChannel == NULL ) {
    length = 0;
    PTRACE(1,"H261\tNo channel to connect to video grabber, close down video transmission thread.");
    return FALSE;
  }

  if( !rawDataChannel->IsOpen() ) {
     PTRACE(1,"H261\tVideo grabber is not initialised, close down video transmission thread.");
     length = 0;
     return FALSE;
  }

  PINDEX w = ((PVideoChannel *)rawDataChannel)->GetGrabWidth();
  PINDEX h = ((PVideoChannel *)rawDataChannel)->GetGrabHeight();

  if (w == 0 ) {
    PTRACE(1,"H261\tVideo grab width is 0 x 0, close down video transmission thread.");
    length=0;
    return FALSE;
  }

  if (w != frameWidth || h != frameHeight) {
    w = isqCIF ? QCIF_WIDTH  : CIF_WIDTH;
    h = isqCIF ? QCIF_HEIGHT : CIF_HEIGHT;
    ((PVideoChannel *)rawDataChannel)->SetGrabberFrameSize(w, h);
    frameWidth = w;
    frameHeight = h;

    videoEncoder->SetSize(frameWidth, frameHeight);
  }

  PINDEX bytesInFrame = (frameWidth * frameHeight * 3) / 2;
  BOOL ok = TRUE;

#define NUMAVG 8

#ifdef INC_ENCODE
  if( !videoEncoder->MoreToIncEncode() ) { // get a new frame
#else
  if( !videoEncoder->PacketsOutStanding() ) { // }get a new frame
#endif
    if (0 == frameNum) { // frame 0 means no frame has been sent yet
      frameStartTime = PTimer::Tick();
    }
    else {
      int frameTimeMs, avgFrameTimeMs, adjFrameTimeMs, avgAdjFrameTimeMs, avgFrameBytes;
      PTimeInterval currentTime;

      currentTime = PTimer::Tick();
      frameTimeMs = (int)(currentTime - frameStartTime).GetMilliSeconds();
      adjFrameTimeMs = frameTimeMs - (int)grabInterval.GetMilliSeconds(); // subtract time possibly blocked in grabbing
      frameStartTime = currentTime;

      sumFrameTimeMs += frameTimeMs;
      avgFrameTimeMs = sumFrameTimeMs / NUMAVG;
      sumFrameTimeMs -= avgFrameTimeMs;
      sumAdjFrameTimeMs += adjFrameTimeMs;
      avgAdjFrameTimeMs = sumAdjFrameTimeMs / NUMAVG;
      sumAdjFrameTimeMs -= avgAdjFrameTimeMs;
      sumFrameBytes += frameBytes;
      avgFrameBytes = sumFrameBytes / NUMAVG;
      sumFrameBytes -= avgFrameBytes;

      //PTRACE(3,"H261\tframeNum                             grabInterval: "
      //  << frameNum << " " << grabInterval.GetMilliSeconds());
      //PTRACE(3,"H261\tframeNum    frameBits       frameTimeMs       Bps: "
      //  << frameNum << " " << (frameBytes*8) << " " << frameTimeMs
      //  << " " << frameBytes*8*1000/frameTimeMs );
      //PTRACE(3,"H261\tframeNum avgFrameBits    avgFrameTimeMs    avgBps: "
      //  << frameNum << " " << (avgFrameBytes*8) << " " << avgFrameTimeMs
      //  << " " << avgFrameBytes*8*1000/avgFrameTimeMs );
      //PTRACE(3,"H261\tframeNum avgFrameBits avgAdjFrameTimeMs avgAdjBps: "
      //  << frameNum << " " << (avgFrameBytes*8) << " " << avgAdjFrameTimeMs
      //  << " " << avgFrameBytes*8*1000/avgAdjFrameTimeMs );

      if (frameNum > NUMAVG) { // do quality adjustment after first NUMAVG frames
        if( 0 != targetFrameTimeMs && (videoBitRateControlModes & DynamicVideoQuality) ) {
          int error; // error signal
          int aerror;
          int act; // action signal
          int newQuality;
          int avgFrameBitRate;
          int targetFrameBits;

          // keep track of average frame size and
          // adjust encoder quality to get targetFrameBits bits per frame
	  if (avgAdjFrameTimeMs)
	    avgFrameBitRate = avgFrameBytes*8*1000 / avgAdjFrameTimeMs; // bits per second
	  else
	    avgFrameBitRate = avgFrameBytes*8*1000;

          targetFrameBits = avgFrameBitRate * targetFrameTimeMs / 1000;
          error = (frameBytes*8) - targetFrameBits; // error signal
          aerror = PABS(error);

          act = 0;
          if (aerror > (targetFrameBits/8) ) {
            if (aerror > (targetFrameBits/4) ) {
              if (aerror > (targetFrameBits/2) ) {
                act = error>0 ? 2 : -4;
              }
              else {
                act = error>0 ? 1 : -2;
              }
            }
            else {
              act = error>0 ? 1 : -1;
            }
          }
          newQuality = videoQuality + act;
          newQuality = PMIN(PMAX(newQuality, videoQMin), videoQMax );
          //PTRACE(3,"H261\tframeNum targetFrameBits frameBits videoQuality newQuality: "
          //  << frameNum << " " << targetFrameBits << " " << (frameBytes*8) << " "
          //  << videoQuality << " "  << newQuality );
          videoQuality = newQuality;
          videoEncoder->SetQualityLevel( videoQuality );

          //PTRACE(3,"H261\tframeNum     avgFrameBitRate     bitRateHighLimit: "
          //  << frameNum << " " << avgFrameBitRate << " " << bitRateHighLimit );
        }
      }
    }

    //NO data is waiting to be read. Go and get some with the read call.
    PTRACE(3,"H261\tRead frame from the video source.");
    PTimeInterval grabStartTime = PTimer::Tick();
    if (rawDataChannel->Read(videoEncoder->GetFramePtr(), bytesInFrame)) {
      PTRACE(3,"H261\tSuccess. Read frame from the video source in "
        << (PTimer::Tick() - grabStartTime).GetMilliSeconds() << " ms.");
      packetNum = 0; // reset packet counter
      // If there is a Renderer attached, display the grabbed video.
      if (((PVideoChannel *)rawDataChannel)->IsRenderOpen() ) {
        ok = RenderFrame(); //use data from grab process.
      }
#ifdef INC_ENCODE
      videoEncoder->PreProcessOneFrame(); //Prepare to generate H261 packets
#else
      videoEncoder->ProcessOneFrame(); //Generate H261 packets
#endif
      frameNum++;
    } else {
      PTRACE(1,"H261\tFailed to read data from video grabber, close down video transmission thread.");
      return FALSE;   //Read failed, return false.
    }
    grabInterval = PTimer::Tick() - grabStartTime;

    /////////////////////////////////////////////////////////////////
    /// THIS VALUE MUST BE CALCULATED AND NOT JUST SET TO 29.97Hz!!!!
    /////////////////////////////////////////////////////////////////
    timestampDelta = 3003;
    frameBytes = 0;

  }
  else {  //if(!videoEncoder->PacketsOutstanding())
    if( 0 != bitRateHighLimit &&
      (videoBitRateControlModes & AdaptivePacketDelay) )
      ; // do nothing now, packet delay will be done later
    else
      PThread::Current()->Sleep(5);  // Place a 5 ms interval betwen
        // packets of the same frame.
    timestampDelta = 0;
  }

#ifdef INC_ENCODE
  videoEncoder->IncEncodeAndGetPacket(buffer,length); //encode & get next packet
  frame.SetMarker(!videoEncoder->MoreToIncEncode());
#else
  videoEncoder->ReadOnePacket(buffer,length); //get next packet on list
  frame.SetMarker(!videoEncoder->PacketsOutStanding());
#endif
  packetNum++;

  // Monitor and report bandwidth usage.
  // If controlling bandwidth, limit the video bandwidth to
  // bitRateHighLimit by introducing a variable delay between packets.
  PTimeInterval currentTime;
  if( 0 != bitRateHighLimit &&
      (videoBitRateControlModes & AdaptivePacketDelay) ) {
    PTimeInterval waitBeforeSending;

    if (newTime != 0) { // calculate delay and wait
      currentTime = PTimer::Tick();
      waitBeforeSending = newTime - currentTime;
      if (waitBeforeSending > 0) PThread::Current()->Sleep(waitBeforeSending);
      // report bit rate & control error for previous packet
      currentTime = PTimer::Tick(); //re-acquire current time after wait
      //PTRACE(3, "H261\tBitRateControl Packet(" << oldPacketNum
      //  << ") Bits: " << oldLength*8
      //  << " Interval: " << (currentTime - oldTime).GetMilliSeconds()
      //  << " Rate: " << oldLength*8000/(currentTime - oldTime).GetMilliSeconds()
      //  << " Error: " << (currentTime - newTime).GetMilliSeconds()
      //  << " Slept: " << waitBeforeSending.GetMilliSeconds() );
    }
    currentTime = PTimer::Tick(); // re-acquire current time due to possible PTRACE delay
    // ms = (bytes * 8) / (bps / 1000)
    if (bitRateHighLimit/1000)
      newTime = currentTime + length*8/(bitRateHighLimit/1000);
    else
      newTime = currentTime + length*8;
  }
  else {
    // monitor & report bit rate
    if (oldTime != 0) { // report bit rate for previous packet
      PTimeInterval currentTime = PTimer::Tick();
      //PTRACE(3, "H261\tBitRateReport  Packet(" << oldPacketNum
      //  << ") Bits: " << oldLength*8
      //  << " Interval: " << (currentTime - oldTime).GetMilliSeconds()
      //  << " Rate: " << oldLength*8000/(currentTime - oldTime).GetMilliSeconds() );
    }
    currentTime = PTimer::Tick(); // re-acquire current time due to possible PTRACE delay
  }
  //oldPacketNum = packetNum; // used only for PTRACE
  oldTime = currentTime;
  oldLength = length;
  frameBytes += length; // count current frame bytes
  return ok;
}



BOOL H323_H261Codec::Write(const BYTE * buffer,
                           unsigned length,
                           const RTP_DataFrame & frame,
                           unsigned & written)
{
  PWaitAndSignal mutex1(videoHandlerActive);

  if( rawDataChannel == NULL ) {
    //Some other task has killed our videohandler. Exit.
    return FALSE;
  }

  BOOL lostPreviousPacket = FALSE;
  if( (++lastSequenceNumber) != frame.GetSequenceNumber() ) {
    lostPreviousPacket = TRUE;
    PTRACE(3,"H261\tDetected loss of one video packet. "
      << lastSequenceNumber << " != "
      << frame.GetSequenceNumber() << " Will recover.");
    lastSequenceNumber = frame.GetSequenceNumber();
    //    SendMiscCommand(H245_MiscellaneousCommand_type::e_lostPartialPicture);
  }

  // always indicate we have written the entire packet
  written = length;

  // H.261 header is usually at start of buffer
  const unsigned char * header = buffer;

  // determine video codec type
  if (videoDecoder == NULL) {
	  // the old behaviour was to choose between IntraP64Decoder and FullP64Decoder,
	  // depending on the header of the first packet.
	  // This lead to bad video quality on some endpoints.
	  // Therefore, we chose to only use the FullP64Decoder
	  videoDecoder = new FullP64Decoder();
	  videoDecoder->marks(rvts);
  }

  videoDecoder->mark(now);
  BOOL ok = videoDecoder->decode(header, length, lostPreviousPacket);
  if (!ok) {
    PTRACE (3, "H261\t Could not decode frame, continuing in hope.");
    return TRUE;
  }
  
  // If the incoming video stream changes size, resize the rendering device.
  ok = Resize(videoDecoder->width(), videoDecoder->height());

  if (ok && frame.GetMarker()) {
    videoDecoder->sync();
    ndblk = videoDecoder->ndblk();
    ok = RenderFrame();
    frameNum++;
    videoDecoder->resetndblk();
  }

  return ok;
}


/* Resize is relevant to the decoder only, as the encoder does not
   change size mid transmission.
*/
BOOL H323_H261Codec::Resize(int _width, int _height)
{
  //Check for a resize is carried out one two level -.
  // a) size change in the receive video stream.

  if ((frameWidth != _width) || (frameHeight != _height) ) {
      frameWidth  = _width;
      frameHeight = _height;

      nblk = (frameWidth * frameHeight) / 64;
      delete [] rvts;
      rvts = new BYTE[nblk];
      memset(rvts, 0, nblk);
      if (videoDecoder != NULL) 
	videoDecoder->marks(rvts);
      if (rawDataChannel != NULL)
	((PVideoChannel *)rawDataChannel)->SetRenderFrameSize(_width, _height);
  }

  return TRUE;
}


BOOL H323_H261Codec::Redraw()
{
  now = 1;
  memset(rvts, 1, nblk);

  return RenderFrame();
}


/* RenderFrame does three things.
   a) Set internal variables
   b) Set size of the display frame. This call happens with every frame.
         A very small overhead.
   c) Display a frame.
*/
BOOL H323_H261Codec::RenderFrame()
{
  int wraptime = now ^ 0x80;
  BYTE * ts = rvts;
  int k;
  for (k = nblk; --k >= 0; ++ts) {
    if (*ts == wraptime)
      *ts = (BYTE)now;
  }

  BOOL ok = TRUE;
  if (rawDataChannel != NULL) {

    //Now display local image.
    ((PVideoChannel *)rawDataChannel)->SetRenderFrameSize(frameWidth, frameHeight);
    PTRACE(6, "H261\tSize of video rendering frame set to " << 
	   frameWidth << "x" << frameHeight << 
	   " for channel:" << ((direction == Encoder) ? "encoding" : "decoding"));

    if (direction == Encoder)
        ok = rawDataChannel->Write((const void *)videoEncoder->GetFramePtr(),frameWidth*frameHeight*3/2);
      else
        ok = rawDataChannel->Write((const void *)videoDecoder->GetFramePtr(),frameWidth*frameHeight*3/2);
  }

  now = (now + 1) & 0xff;

  return ok;
}


void H323_H261Codec::SetTxQualityLevel(int qLevel)
{
  videoQuality = PMIN(videoQMax, PMAX(qLevel, videoQMin));

  // If a video encoder is running and if there is no
  // dynamic video quality control, update the value
  // in the encoder
  if (!(DynamicVideoQuality & videoBitRateControlModes) && (videoEncoder != NULL))
    videoEncoder->SetQualityLevel (videoQuality);
  PTRACE(3, "H261\tvideoQuality set to " << videoQuality);
}

void H323_H261Codec::SetTxMinQuality(int qlevel) {
  videoQMin = PMIN(videoQMax, PMAX(1, qlevel));
  PTRACE(3, "H261\tvideoQMin set to " << videoQMin);
}

void H323_H261Codec::SetTxMaxQuality(int qlevel) {
  videoQMax = PMAX(videoQMin, PMIN(31, qlevel));
  PTRACE(3, "H261\tvideoQMax set to " << videoQMax);
}

void H323_H261Codec::SetBackgroundFill(int idle)
{
  fillLevel = PMIN(99, PMAX(idle,1));

  // If a video encoder is running and if there is no
  // dynamic video quality control, update the value
  // in the encoder
  if (!(DynamicVideoQuality & videoBitRateControlModes) && (NULL != videoEncoder))
    videoEncoder->SetBackgroundFill (idle);
  PTRACE(3, "H261\tfillLevel set to " << fillLevel);
}


void H323_H261Codec::OnFastUpdatePicture()
{
  PTRACE(3,"H261\tFastUpdatePicture received");
  PWaitAndSignal mutex1(fastUpdateMutex);

  doFastUpdate = TRUE;
}


void H323_H261Codec::OnLostPartialPicture()
{
  PTRACE(3,"H261\tLost partial picture message ignored, not implemented");
}


void H323_H261Codec::OnLostPicture()
{
  PTRACE(3,"H261\tLost picture message ignored, not implemented");
}


#endif // NO_H323_VIDEO


/////////////////////////////////////////////////////////////////////////////
