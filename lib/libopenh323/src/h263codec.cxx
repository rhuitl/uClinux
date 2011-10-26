/*
 * h263codec.cxx   
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
 * Portions of this code were written by Guilhem Tardy, with financial
 *  assistance from March Networks (http://www.marchnetworks.com)
 *
 * Portions of this code were written with the financial assistance of 
 *          AliceStreet (http://www.alicestreet.com) 
 *
 * Thanks to March Networks, AliceStreet, Guilhem Tardy  for releasing
 * your work back to the openh323 group.
 *
 * Contributor(s): Guilhem Tardy (gtardy@marchnetworks.com)
 *
 * $Log: h263codec.cxx,v $
 * Revision 1.28  2005/06/07 07:59:11  csoutheren
 * Applied patch 1176459 for PocketPC. Thanks to Matthias Weber
 *
 * Revision 1.27  2004/05/04 03:33:33  csoutheren
 * Added guards against comparing certain kinds of Capabilities
 *
 * Revision 1.26  2004/04/19 03:48:19  dereksmithies
 * Adjust Acknowledgements. Thanks to Guilhem Tardy for describing the error.
 *
 * Revision 1.25  2004/04/04 13:56:06  rjongbloed
 * Changes to support native C++ Run Time Type Information
 *
 * Revision 1.24  2003/08/29 00:33:22  dereksmithies
 * Add fix for printing vic messages to the log file. MANY thanks to Niklas Ogren
 *
 * Revision 1.23  2003/08/04 00:03:41  dereksmithies
 * Reorganise test of H323_VICH263 switch
 *
 * Revision 1.22  2003/08/01 02:01:42  csoutheren
 * Changed to disable when VIC 263 not installed
 *
 * Revision 1.21  2003/07/29 03:57:00  dereksmithies
 * Remove weird boxes on startup.
 *
 * Revision 1.20  2003/07/24 08:09:18  dereksmithies
 * Update to use vich263 codec, instead of ffmpeg
 *
 * Revision 1.19  2003/06/14 05:54:23  rjongbloed
 * Fixed MSVC warning.
 * Fixed what seemed an obvious mistake using boolean or operator (||) instead
 *   of the bitwise or operator (|).
 *
 * Revision 1.18  2003/06/12 00:24:32  dereksmithies
 * Modify so QCIF-CIF behaviour similar to that for h261codec.cxx
 *
 * Revision 1.17  2003/06/10 01:37:25  dereksmithies
 * Changes so it should not crash under windows/release mode
 *
 * Revision 1.16  2003/06/06 06:32:08  rjongbloed
 * Fixed MSVC warning
 *
 * Revision 1.15  2003/06/06 05:18:54  dereksmithies
 * Fix startup delay bug. Remove all large packets from the network. Improve reliability.
 *
 * Revision 1.14  2003/06/03 05:01:23  rjongbloed
 * Fixed some trace logging (removed usage of cerr)
 *
 * Revision 1.13  2003/06/03 00:49:01  dereksmithies
 * Fix divide by zero error, which happens on win95 & win98 machines.
 *
 * Revision 1.12  2003/06/02 07:56:56  rjongbloed
 * Fixed media format passed to ancestor codec class
 *
 * Revision 1.11  2003/05/27 04:20:59  dereksmithies
 * Fix so that codec resizes correctly after capability exchange
 * No longer crashes if one endpoint is CIF, other is QCIF.
 *
 * Revision 1.10  2003/05/16 04:42:24  rjongbloed
 * Removed extraneous code, and other cosmetic changes.
 * Fixed compare function for capability.
 * Extra trace logging.
 *
 * Revision 1.9  2003/05/15 01:35:27  dereksmithies
 * Frame length fix
 *
 * Revision 1.8  2003/05/14 13:51:51  rjongbloed
 * Removed hack of using special payload type for H.263 for a method which
 *   would be less prone to failure in the future.
 * Removed static "initialisation" function as this should be done
 *   internally and not in the application.
 * Changed media format to be straight H.263 and not OpalH.263
 * Moved Win32 stderr output in ffmpeg AVCODEC interception from
 *   application to library.
 * Fixed some warnings.
 *
 * Revision 1.7  2003/05/14 03:07:17  rjongbloed
 * Made sure video buffer is large enough
 *
 * Revision 1.6  2003/05/05 11:59:25  robertj
 * Changed to use autoconf style selection of options and subsystems.
 *
 * Revision 1.5  2003/05/02 04:21:30  craigs
 * Added lots of extra H.263 support
 *
 * Revision 1.4  2003/04/21 21:50:22  dereks
 * Implement suggestion from Guilhem Tardy. Many thanks.
 *
 * Revision 1.3  2003/04/16 04:26:57  dereks
 * Initial release of h263 codec, which utilises the ffmpeg library.
 * Thanks to Guilhem Tardy, and to AliceStreet.
 *
 * Revision 1.2  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.1  2002/05/19 22:31:12  dereks
 * Initial release of stub file for h263 codec. Thanks Guilhem Tardy.
 */

/*
 *  Initial release notes from Guilhem Tardy::
 *
 * Added support for video capabilities & codec, still needs the actual codec itself!
 * The code for varying bit rate is copied from h261codec.cxx,
 * until it is moved to a separate file common to both video codecs.
 *
 */
#include <ptlib.h>

#ifdef __GNUC__
#pragma implementation "h263codec.h"
#endif

#include "h263codec.h"
#if defined(H323_VICH263)


#include "h245.h"
#include "rtp.h"

#if defined(_MSC_VER)
#ifndef _WIN32_WINCE
#pragma comment(lib, H323_VICH263_LIBRARY)
#endif
#endif


#include <encoder-h263.h>
#include <decoder-h263.h>

/* #define INC_ENCODE 1 */

//////////////////////////////////////////////////////////////////////////////

static void h263_vic_printon(char * str);
static void h263_vic_printon(char * str)
{
  PTRACE(6, "Vic H263\t" << str);
  strlen(str);   /*Stop any compiler warning about unused variable*/
}


class VicH263Link : public PObject
{
  PCLASSINFO(VicH263Link, PObject)
    
    public:
  VicH263Link();
};

VicH263Link::VicH263Link()
{
  vich263_set_print_fn(h263_vic_printon);
}

VicH263Link vicLink;

///////////////////////////////////////////////////////////////////////////////////////

#define new PNEW


static OpalMediaFormat const H263_MediaFormat("H.263",
                                              OpalMediaFormat::DefaultVideoSessionID,
                                              RTP_DataFrame::H263,
                                              FALSE,  // No jitter for video
                                              180000, // bits/sec
                                              2000,   // Not sure of this value!
                                              0,      // No intrinsic time per frame
                                              OpalMediaFormat::VideoTimeUnits);


//////////////////////////////////////////////////////////////////////////////

H323_H263Capability::H323_H263Capability(unsigned _sqcifMPI,
					 unsigned _qcifMPI,
					 unsigned _cifMPI,
					 unsigned _cif4MPI,
					 unsigned _cif16MPI,
					 unsigned _maxBitRate,
					 unsigned _videoFrameRate,
					 BOOL _unrestrictedVector,
					 BOOL _arithmeticCoding,
					 BOOL _advancedPrediction,
					 BOOL _pbFrames,
					 BOOL _temporalSpatialTradeOff,
					 unsigned _hrd_B,
					 unsigned _bppMaxKb,
					 unsigned _slowSqcifMPI,
					 unsigned _slowQcifMPI,
					 unsigned _slowCifMPI,
					 unsigned _slowCif4MPI,
					 unsigned _slowCif16MPI,
					 BOOL _errorCompensation)
{
  sqcifMPI = (_sqcifMPI>0?_sqcifMPI:-(int)_slowSqcifMPI);
  qcifMPI = (_qcifMPI>0?_qcifMPI:-(int)_slowQcifMPI);
  cifMPI = (_cifMPI>0?_cifMPI:-(int)_slowCifMPI);
  cif4MPI = (_cif4MPI>0?_cif4MPI:-(int)_slowCif4MPI);
  cif16MPI = (_cif16MPI>0?_cif16MPI:-(int)_slowCif16MPI);

  maxBitRate = _maxBitRate;
  videoFrameRate = _videoFrameRate;

  temporalSpatialTradeOff = _temporalSpatialTradeOff;
  pbFrames = _pbFrames;
  advancedPrediction = _advancedPrediction;
  arithmeticCoding = _arithmeticCoding;
  unrestrictedVector = _unrestrictedVector;

  hrd_B = _hrd_B;
  bppMaxKb = _bppMaxKb;

  errorCompensation = _errorCompensation;
}


PObject * H323_H263Capability::Clone() const
{
  return new H323_H263Capability(*this);
}


PObject::Comparison H323_H263Capability::Compare(const PObject & obj) const
{
  if (!PIsDescendant(&obj, H323_H263Capability))
    return LessThan;

  Comparison result = H323Capability::Compare(obj);
  if (result != EqualTo) 
    return result;

  const H323_H263Capability & other = (const H323_H263Capability &)obj;

/*
  if ((sqcifMPI > other.sqcifMPI) ||
      (qcifMPI > other.qcifMPI) ||
      (cifMPI > other.cifMPI) ||
      (cif4MPI > other.cif4MPI) ||
      (cif16MPI > other.cif16MPI))
    return GreaterThan;

  if ((cif16MPI < other.cif16MPI) ||
      (cif4MPI < other.cif4MPI) ||
      (cifMPI < other.cifMPI) ||
      (qcifMPI < other.qcifMPI))
    return LessThan;
*/

  if (
((sqcifMPI > 0) && (other.sqcifMPI > 0)) ||
((qcifMPI > 0) && (other.qcifMPI > 0)) ||
((cifMPI > 0) && (other.cifMPI > 0)) ||
((cif4MPI > 0) && (other.cif4MPI > 0)) ||
((cif16MPI > 0) && (other.cif16MPI > 0))
)
    return EqualTo;

  if (qcifMPI > 0)
    return LessThan;

  return GreaterThan;


  return EqualTo;
}


PString H323_H263Capability::GetFormatName() const
{
  PString ret = H263_MediaFormat;

  if (sqcifMPI)
    ret += "-SQCIF";

  if (qcifMPI)
    ret += "-QCIF";

  if (cifMPI)
    ret += "-CIF";

  if (cif4MPI)
    ret += "-CIF4";

  if (cif16MPI)
    ret += "-CIF16";

  return ret;
}


unsigned H323_H263Capability::GetSubType() const
{
  return H245_VideoCapability::e_h263VideoCapability;
}


BOOL H323_H263Capability::OnSendingPDU(H245_VideoCapability & cap) const
{
  cap.SetTag(H245_VideoCapability::e_h263VideoCapability);

  H245_H263VideoCapability & h263 = cap;
  if (sqcifMPI > 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_sqcifMPI);
    h263.m_sqcifMPI = sqcifMPI;
  }
  if (qcifMPI > 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_qcifMPI);
    h263.m_qcifMPI = qcifMPI;
  }
  if (cifMPI > 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_cifMPI);
    h263.m_cifMPI = cifMPI;
  }
  if (cif4MPI > 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_cif4MPI);
    h263.m_cif4MPI = cif4MPI;
  }
  if (cif16MPI > 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_cif16MPI);
    h263.m_cif16MPI = cif16MPI;
  }
  h263.m_temporalSpatialTradeOffCapability = temporalSpatialTradeOff;
  h263.m_maxBitRate = maxBitRate;
  if (sqcifMPI < 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_slowSqcifMPI);
    h263.m_slowSqcifMPI = -sqcifMPI;
  }
  if (qcifMPI < 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_slowQcifMPI);
    h263.m_slowQcifMPI = -qcifMPI;
  }
  if (cifMPI < 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_slowCifMPI);
    h263.m_slowCifMPI = -cifMPI;
  }
  if (cif4MPI < 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_slowCif4MPI);
    h263.m_slowCif4MPI = -cif4MPI;
  }
  if (cif16MPI < 0) {
    h263.IncludeOptionalField(H245_H263VideoCapability::e_slowCif16MPI);
    h263.m_slowCif16MPI = -cif16MPI;
  }

  return TRUE;
}


BOOL H323_H263Capability::OnSendingPDU(H245_VideoMode & pdu) const
{
  pdu.SetTag(H245_VideoMode::e_h263VideoMode);
  H245_H263VideoMode & mode = pdu;
  mode.m_resolution.SetTag(cif16MPI ? H245_H263VideoMode_resolution::e_cif16
			  :(cif4MPI ? H245_H263VideoMode_resolution::e_cif4
			   :(cifMPI ? H245_H263VideoMode_resolution::e_cif
			    :(qcifMPI ? H245_H263VideoMode_resolution::e_qcif
			     : H245_H263VideoMode_resolution::e_sqcif))));
  mode.m_bitRate = maxBitRate;
  mode.m_unrestrictedVector = unrestrictedVector;
  mode.m_arithmeticCoding = arithmeticCoding;
  mode.m_advancedPrediction = advancedPrediction;
  mode.m_pbFrames = pbFrames;
  mode.m_errorCompensation = errorCompensation;

  return TRUE;
}


BOOL H323_H263Capability::OnReceivedPDU(const H245_VideoCapability & cap)
{
  if (cap.GetTag() != H245_VideoCapability::e_h263VideoCapability)
    return FALSE;

  const H245_H263VideoCapability & h263 = cap;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_sqcifMPI))
    sqcifMPI = h263.m_sqcifMPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowSqcifMPI))
    sqcifMPI = -(int)h263.m_slowSqcifMPI;
  else
    sqcifMPI = 0;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_qcifMPI))
    qcifMPI = h263.m_qcifMPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowQcifMPI))
    qcifMPI = -(int)h263.m_slowQcifMPI;
  else
    qcifMPI = 0;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_cifMPI))
    cifMPI = h263.m_cifMPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowCifMPI))
    cifMPI = -(int)h263.m_slowCifMPI;
  else
    cifMPI = 0;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_cif4MPI))
    cif4MPI = h263.m_cif4MPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowCif4MPI))
    cif4MPI = -(int)h263.m_slowCif4MPI;
  else
    cif4MPI = 0;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_cif16MPI))
    cif16MPI = h263.m_cif16MPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowCif16MPI))
    cif16MPI = -(int)h263.m_slowCif16MPI;
  else
    cif16MPI = 0;
  maxBitRate = h263.m_maxBitRate;
  unrestrictedVector = h263.m_unrestrictedVector;
  arithmeticCoding = h263.m_arithmeticCoding;
  advancedPrediction = h263.m_advancedPrediction;
  pbFrames = h263.m_pbFrames;
  temporalSpatialTradeOff = h263.m_temporalSpatialTradeOffCapability;
  hrd_B = h263.m_hrd_B;
  bppMaxKb = h263.m_bppMaxKb;
  errorCompensation = h263.m_errorCompensation;

  return TRUE;
}


H323Codec * H323_H263Capability::CreateCodec(H323Codec::Direction direction) const
{     
  return new H323_H263Codec(direction, sqcifMPI, qcifMPI, cifMPI, cif4MPI, cif16MPI, maxBitRate, videoFrameRate);
}

//////////////////////////////////////////////////////////////////////////////


H323_H263Codec::H323_H263Codec(Direction dir,
			       unsigned _sqcifMPI,
			       unsigned _qcifMPI,
			       unsigned _cifMPI,
			       unsigned _cif4MPI,
			       unsigned _cif16MPI,
			       unsigned _maxBitRate,
			       unsigned _videoFrameRate)
  : H323VideoCodec(H263_MediaFormat, dir)
{
  PTRACE(3, "H263\t" << (dir == Encoder ? "En" : "De") 
	 << "coder created. Data rate=" << _maxBitRate
	 << " Frame rate=" << _videoFrameRate);

  bitRateHighLimit = _maxBitRate;
  if (bitRateHighLimit == 0) {
    PTRACE(3, "H263\tData Rate is set to 1000 Kb/sec, as supplied value (0) is invalid");
    bitRateHighLimit = 1000 * 1024;
  }
  
  framesPerSec = _videoFrameRate;
  if (framesPerSec == 0) {
    PTRACE(3, "H263\tFrame Rate is set to 25 frames/sec, as supplied value (0) is invalid");
    framesPerSec = 25;
  }

  int shifts = -1;
  if (_sqcifMPI) { 
    shifts = 0;     PTRACE(3, "H263\t" << (dir == Encoder ? "En" : "De") << "coder for _sqcifMPI ");
  }
  if (_qcifMPI) {
    shifts = 1;  PTRACE(3, "H263\t" << (dir == Encoder ? "En" : "De") << "coder for _qcifMPI"); 
  }
  if (_cifMPI) { 
    shifts = 2; PTRACE(3, "H263\t" << (dir == Encoder ? "En" : "De") << "coder for _cifMPI");
  }
  if (_cif4MPI) {
    shifts = 3; PTRACE(3, "H263\t" << (dir == Encoder ? "En" : "De") << "coder for _cif4MPI");
  }
  if (_cif16MPI) {
    shifts = 4; PTRACE(3, "H263\t" << (dir == Encoder ? "En" : "De") << "coder for _cif16MPI");
  }

  if (shifts < 0) {
    PTRACE(1, "H263\tERROR in definition of h263 size");
    return;
  }

  PTRACE(3, "H263\t" << (dir == Encoder ? "En" : "De") << "coder created." 
	 << "for a size of " << (88 << shifts) << "x" << (72 << shifts));
  
  Resize(88 << shifts , 72 << shifts); //Fill picture structure, open codec.
  frameNum = 0;

  InitialiseCodec();
}


H323_H263Codec::~H323_H263Codec()
{
  PWaitAndSignal mutex1(videoHandlerActive);

  CloseCodec();

  if (videoDecoder) {
    delete videoDecoder;
    videoDecoder = NULL;
  }

  if (videoEncoder){
    delete videoEncoder;
    videoEncoder = NULL;
  }
}

void H323_H263Codec::InitialiseCodec()
{ 
   // no video decoder until we receive a packet
   videoDecoder = NULL;

   // no video encoder until we receive a packet
   videoEncoder = NULL;
}

void H323_H263Codec::CloseCodec()
{
  PTRACE(6, "H263\tClose h263 video " <<(direction == Encoder ? "En" : "De") << "coder");
}




/* Notes:
Quality was primarily for NetMeeting?
fillLevel simply set the greyscale of the background
*/


//This function grabs, displays, and compresses a video frame into
//into H263 packets.
//Get another frame if all packets of previous frame have been sent.
//Get next packet on list and send that one.
//Render the current frame if all of its packets have been sent.
BOOL H323_H263Codec::Read(BYTE * buffer,
                          unsigned & length,
                          RTP_DataFrame & frame)
{
  PWaitAndSignal mutex1(videoHandlerActive);
  PTRACE(6,"H263\tAcquire next packet from h263 encoder.\n");

  if (videoEncoder == NULL) {
      videoEncoder = new H263Encoder(videoQuality, fillLevel);
  }

  if (rawDataChannel == NULL) {
    length = 0;
    PTRACE(1,"H263\tNo channel to connect to video grabber, close down video transmission thread.");
    return FALSE;
  }

  if (!rawDataChannel->IsOpen()) {
     PTRACE(1,"H263\tVideo grabber is not initialised, close down video transmission thread.");
     length = 0;
     return FALSE;
  }

  frameWidth  = ((PVideoChannel *)rawDataChannel)->GetGrabWidth();
  frameHeight = ((PVideoChannel *)rawDataChannel)->GetGrabHeight();
  PTRACE(6, "H263\tVideo grab size is " << frameWidth << "x" << frameHeight);

  if (frameWidth == 0) {
    PTRACE(1,"H263\tVideo grab width is 0 x 0, close down video transmission thread.");
    length=0;
    return FALSE;
  }

  videoEncoder->SetSize(frameWidth, frameHeight);

  PINDEX bytesInFrame = 0;
  BOOL ok = TRUE;

#define NUMAVG 8

#ifdef INC_ENCODE
  if (!videoEncoder->MoreToIncEncode()) { // get a new frame
#else
  if (!videoEncoder->PacketsOutStanding()) { // }get a new frame
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

      //PTRACE(3,"H263\tframeNum                             grabInterval: "
      //  << frameNum << " " << grabInterval.GetMilliSeconds());
      //PTRACE(3,"H263\tframeNum    frameBits       frameTimeMs       Bps: "
      //  << frameNum << " " << (frameBytes*8) << " " << frameTimeMs
      //  << " " << frameBytes*8*1000/frameTimeMs);
      //PTRACE(3,"H263\tframeNum avgFrameBits    avgFrameTimeMs    avgBps: "
      //  << frameNum << " " << (avgFrameBytes*8) << " " << avgFrameTimeMs
      //  << " " << avgFrameBytes*8*1000/avgFrameTimeMs);
      //PTRACE(3,"H263\tframeNum avgFrameBits avgAdjFrameTimeMs avgAdjBps: "
      //  << frameNum << " " << (avgFrameBytes*8) << " " << avgAdjFrameTimeMs
      //  << " " << avgFrameBytes*8*1000/avgAdjFrameTimeMs);

      if (frameNum > NUMAVG) { // do quality adjustment after first NUMAVG frames
        if (0 != targetFrameTimeMs && (videoBitRateControlModes & DynamicVideoQuality)) {
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
          if (aerror > (targetFrameBits/8)) {
            if (aerror > (targetFrameBits/4)) {
              if (aerror > (targetFrameBits/2)) {
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
          newQuality = PMIN(PMAX(newQuality, videoQMin), videoQMax);
          //PTRACE(3,"H263\tframeNum targetFrameBits frameBits videoQuality newQuality: "
          //  << frameNum << " " << targetFrameBits << " " << (frameBytes*8) << " "
          //  << videoQuality << " "  << newQuality);
          videoQuality = newQuality;

          videoEncoder->SetQualityLevel(videoQuality);

          //PTRACE(3,"H263\tframeNum     avgFrameBitRate     bitRateHighLimit: "
          //  << frameNum << " " << avgFrameBitRate << " " << bitRateHighLimit);
        }
      }
    }

    //NO data is waiting to be read. Go and get some with the read call.
    PTRACE(3,"H263\tRead frame from the video source.");
    PTimeInterval grabStartTime = PTimer::Tick();
    if (rawDataChannel->Read(videoEncoder->GetFramePtr(), bytesInFrame)) {
      PTRACE(3,"H263\tSuccess. Read frame from the video source in "
	     << (PTimer::Tick() - grabStartTime).GetMilliSeconds() << " ms.");

      if (frameNum == 0) {
	memset(videoEncoder->GetFramePtr(), 64, (frameWidth * frameHeight * 3) >> 1);     
      }

      packetNum = 0; // reset packet counter
      
      // If there is a Renderer attached, display the grabbed video.
      if (((PVideoChannel *)rawDataChannel)->IsRenderOpen()) {
	ok = RenderFrame(); //use data from grab process.
	}
      
#ifdef INC_ENCODE
      videoEncoder->PreProcessOneFrame(); //Prepare to generate H263 packets
#else
      videoEncoder->ProcessOneFrame(); //Generate H263 packets
#endif
      frameNum++;
    } else {
      PTRACE(1,"H263\tFailed to read data from video grabber, close down video transmission thread.");
      return FALSE;   //Read failed, return false.
    }
    grabInterval = PTimer::Tick() - grabStartTime;

    /////////////////////////////////////////////////////////////////
    /// THIS VALUE MUST BE CALCULATED AND NOT JUST SET TO 29.97Hz!!!!
    /////////////////////////////////////////////////////////////////
    timestampDelta = 3003;
    frameBytes = 0;

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
  if (0 != bitRateHighLimit &&
      (videoBitRateControlModes & AdaptivePacketDelay)) {
    PTimeInterval waitBeforeSending;

    if (newTime != 0) { // calculate delay and wait
      currentTime = PTimer::Tick();
      waitBeforeSending = newTime - currentTime;
      if (waitBeforeSending > 0) PThread::Current()->Sleep(waitBeforeSending);
      // report bit rate & control error for previous packet
      currentTime = PTimer::Tick(); //re-acquire current time after wait
      //PTRACE(3, "H263\tBitRateControl Packet(" << oldPacketNum
      //  << ") Bits: " << oldLength*8
      //  << " Interval: " << (currentTime - oldTime).GetMilliSeconds()
      //  << " Rate: " << oldLength*8000/(currentTime - oldTime).GetMilliSeconds()
      //  << " Error: " << (currentTime - newTime).GetMilliSeconds()
      //  << " Slept: " << waitBeforeSending.GetMilliSeconds());
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
      //PTRACE(3, "H263\tBitRateReport  Packet(" << oldPacketNum
      //  << ") Bits: " << oldLength*8
      //  << " Interval: " << (currentTime - oldTime).GetMilliSeconds()
      //  << " Rate: " << oldLength*8000/(currentTime - oldTime).GetMilliSeconds());
    }
    currentTime = PTimer::Tick(); // re-acquire current time due to possible PTRACE delay
  }
  //oldPacketNum = packetNum; // used only for PTRACE
  oldTime = currentTime;
  oldLength = length;
  frameBytes += length; // count current frame bytes
  return ok;
}




BOOL H323_H263Codec::Write(const BYTE * buffer,
                           unsigned length,
                           const RTP_DataFrame & frame,
                           unsigned & written)
{
  PWaitAndSignal mutex1(videoHandlerActive);

  if (rawDataChannel == NULL) {
    //Some other task has killed our videohandler. Exit.
    return FALSE;
  }

  BOOL lostPreviousPacket = FALSE;
  if ((++lastSequenceNumber) != frame.GetSequenceNumber()) {
    lostPreviousPacket = TRUE;
    PTRACE(3,"H263\tDetected loss of one video packet. "
      << lastSequenceNumber << " != "
      << frame.GetSequenceNumber() << " Will recover.");
    lastSequenceNumber = frame.GetSequenceNumber();
    //    SendMiscCommand(H245_MiscellaneousCommand_type::e_lostPartialPicture);
  }

  // always indicate we have written the entire packet
  written = length;

  // H.263 header is usually at start of buffer
  const unsigned char * header = buffer;
  // adjust for any contributing source (see SSRC in RFC1889)
  PINDEX cnt = frame.GetContribSrcCount();
  if (cnt > 0) {
    header += cnt * 4;
    length -= cnt * 4;
  }

  // determine video codec type
  if (videoDecoder == NULL) {
/*
    if ((*header & 2) && !(*header & 1)) // check value of I field in header
		AWM: Intra vs. Full?
*/
      videoDecoder = new H263Decoder();
      videoDecoder->marks(rvts);
  }

  videoDecoder->mark(now);
  BOOL ok = videoDecoder->decode(header, length, (char)lostPreviousPacket,
  	(char)frame.GetMarker(), frame.GetSequenceNumber());
  if (!ok) {
    PTRACE (3, "H263\t Could not decode frame, continuing in hope.");
    return TRUE;
  }
  
  // If the incoming video stream changes size, resize the rendering device.
  ok = Resize(videoDecoder->width(), videoDecoder->height());

  if (ok && frame.GetMarker()) {
    videoDecoder->sync();
    ndblk = videoDecoder->ndblk();
    ok = RenderFrame();
    videoDecoder->resetndblk();
  }

  return ok;
}




BOOL H323_H263Codec::Resize(int _width, int _height)
{
  if ((frameWidth == _width) && (frameHeight == _height)) 
    return TRUE;

  PTRACE(6, "H263\t" << (direction == Encoder ? "En" : "De") << "coder resizing to "
	 << _width << "x" << _height << ".");


  frameWidth = _width;
  frameHeight = _height;

  return TRUE;
}
 

/* RenderFrame does two things:
   a) Set size of the display frame. This call happens with every frame.
	 A very small overhead.
   b) Display a frame.
*/

BOOL H323_H263Codec::RenderFrame(const void * buffer)
{
  if (rawDataChannel == NULL)
    return TRUE;

  //Now display local image.
  ((PVideoChannel *)rawDataChannel)->SetRenderFrameSize(frameWidth, frameHeight);

  if (buffer == NULL)
    return TRUE;

  return rawDataChannel->Write(buffer, 0 /*unused parameter*/);
}

/* AWM: Look-alike to H.261 implementation */
BOOL H323_H263Codec::RenderFrame()
{
  void *srcData;
  
  if (direction == Encoder)
    srcData = videoEncoder->GetFramePtr();
  else
    srcData = videoDecoder->GetFramePtr();

  return  RenderFrame(srcData);
}




void H323_H263Codec::SetTxQualityLevel(int qLevel)
{
  int qualityLevel = PMIN(14, PMAX(qLevel,3));

  int lowLimit = PMIN(10, qualityLevel - 2);
  int highLimit = qualityLevel + 12;

  videoQuality = qLevel;
  videoQMin = lowLimit;       
  videoQMax = highLimit;
}


void H323_H263Codec::SetBackgroundFill(int idle)
{
    fillLevel = PMIN(99, PMAX(idle,1));
}


void H323_H263Codec::OnLostPartialPicture()
{
  PTRACE(3, "H263\tLost partial picture message ignored, not implemented");
}


void H323_H263Codec::OnLostPicture()
{
  PTRACE(3, "H263\tLost picture message ignored, not implemented");
}

 
//////////////////////////////////////////////////////////////////////

#endif // H323_VICH263

