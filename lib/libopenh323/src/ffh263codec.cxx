/*
 * ffh263codec.cxx
 *
 * Non standard implementation of h263+ based on ffmpeg. (or reported as avcodec)
 *
 * H.323 protocol handler
 *
 * Open H323 Library
 * 
 * Copyright (c) 2001 March Networks Corporation
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
 * Portions of this code were written with the financial assistance of 
 *          AliceStreet (http://www.alicestreet.com) 
 *
 * Contributor(s): Guilhem Tardy (gtardy@salyens.com)
 *
 * $Log: ffh263codec.cxx,v $
 * Revision 1.10  2004/12/08 02:03:59  csoutheren
 * Fixed problem with detection of non-FFH.263
 *
 * Revision 1.9  2004/05/12 23:18:34  csoutheren
 * Adjusted copyright notices for ffh263 and rfc2190 files
 *
 * Revision 1.8  2004/04/26 10:44:14  csoutheren
 * Included most recent H.263 stubs from Guilhem Tardy
 * This appears to fix the stability problems on transmitting video from Linux
 *
 * Revision 1.7  2004/04/22 22:35:00  csoutheren
 * Fixed mispelling of Guilhem Tardy - my apologies to him
 *
 * Revision 1.6  2004/04/22 14:22:21  csoutheren
 * Added RFC 2190 H.263 code as created by Guilhem Tardy and AliceStreet
 * Many thanks to them for their contributions.
 *
 * Revision 1.5  2003/08/08 01:52:14  dereksmithies
 * Make use of ffmpeg library work correctly on multi CPU boxes.
 *
 * Revision 1.4  2003/08/04 00:03:35  dereksmithies
 * Reorganise test of H323_AVCODEC switch
 *
 * Revision 1.3  2003/07/31 05:08:24  dereksmithies
 * Switch to manual packet fragment technique. Much more reliable, especially so on windows.
 *
 * Revision 1.2  2003/07/29 03:33:41  dereksmithies
 * add bug fix which prevents random Crashes on windows.
 *
 * Revision 1.1  2003/07/24 05:22:18  dereksmithies
 * Moved ffmpeg h263 support to this file, and designate as non standard.
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
#include "h263codec.h"

#ifdef __GNUC__
#pragma implementation "ffh263codec.h"
#endif

#include "ffh263codec.h"

#ifdef H323_RFC2190_AVCODEC
//#pragma message ("Non-standard H.263 codecs disabled as RFC2190 H.263 is enabled")
#elif H323_AVCODEC

#include "h245.h"
#include "rtp.h"
#include "h323pluginmgr.h"

#define  MSVC_OPENH323 1

extern "C" {
#include <avcodec.h>
};


//#if defined(_MSC_VER)
//#pragma comment(lib, H323_FFMPEG_LIBRARY)
//#endif

//////////////////////////////////////////////////////////////////////////////
static void h263_ffmpeg_printon(char * str);
static void h263_ffmpeg_printon(char * str)
{
  PTRACE(6, "FFMPEG\t" << str);
  strlen(str);   /*Stop any compiler warning about unused variable*/
}

//////////////////////////////////////////////////

class FfmpgLink : public H323DynaLink
{
  PCLASSINFO(FfmpgLink, H323DynaLink)
    
 public:
  FfmpgLink();
  ~FfmpgLink();

  AVCodec *AvcodecFindDecoderByName(const char *name);
  AVCodec *AvcodecFindEncoderByName(const char *name);
  AVCodecContext *AvcodecAllocContext(void);

  AVFrame *AvcodecAllocFrame(void);

  BOOL IsLoaded();

  int AvcodecClose(AVCodecContext *ctx);
  int AvcodecDecodeVideo(AVCodecContext *ctx, AVFrame *picture, int *got_picture_ptr, BYTE *buf, int buf_size);
  int AvcodecEncodeVideo(AVCodecContext *ctx, BYTE *buf, int buf_size, const AVFrame *pict);
  int AvcodecOpen(AVCodecContext *ctx, AVCodec *codec);

  void AFavcodecRegisterAll(void);
  void AvcodecGetContextDefaults(AVCodecContext *s);
  void AvcodecInit(void);
  void AvcodecSetPrintFn(void (*print_fn)(char *));

protected:
  AVCodec *(*Favcodec_find_decoder_by_name)(const char *name);
  AVCodec *(*Favcodec_find_encoder_by_name)(const char *name);
  AVCodecContext *(*Favcodec_alloc_context)(void);
  AVFrame *(*Favcodec_alloc_frame)(void);
  int (*Favcodec_close)(AVCodecContext *ctx);
  int (*Favcodec_decode_video)(AVCodecContext *ctx, AVFrame *picture, int *got_picture_ptr, BYTE *buf, int buf_size);
  int (*Favcodec_encode_video)(AVCodecContext *ctx, BYTE *buf, int buf_size, const AVFrame *pict);
  int (*Favcodec_open)(AVCodecContext *ctx, AVCodec *codec);

  void (*Favcodec_get_context_defaults)(AVCodecContext *s);
  void (*Favcodec_init)(void);
  void (*Favcodec_set_print_fn)(void (*print_fn)(char *));
  void (*Favcodec_register_all)(void);
};           

//////////////////////////////////////////////////////////////////////////////

#define new PNEW

FfmpgLink::FfmpgLink()
  : H323DynaLink("libavcodec")
{
  Load();
  if (!PDynaLink::IsLoaded()) 
    return;

  if (!GetFunction("avcodec_init",                  (Function &)Favcodec_init)) {
    cerr <<  "Failed to load avcodec_int" << endl;
    return;
  }

  if (!GetFunction("avcodec_register_all",          (Function &)Favcodec_register_all)) {
    cerr <<  "Failed to load avcodec_register_all" << endl;
    return;
  }

  if (!GetFunction("avcodec_find_encoder_by_name",   (Function &)Favcodec_find_encoder_by_name)) {
    cerr <<  "Failed to load avcodec_find_encoder_by_name" << endl;
    return;
  }

  if (!GetFunction("avcodec_find_decoder_by_name",   (Function &)Favcodec_find_decoder_by_name)) {
    cerr <<  "Failed to load avcodec_find_decoder_by_name" << endl;
    return;
  }

  if (!GetFunction("avcodec_alloc_context",         (Function &)Favcodec_alloc_context)) {
    cerr <<  "Failed to load avcodec_alloc_context" << endl;
    return;
  }

  if (!GetFunction("avcodec_alloc_frame",           (Function &)Favcodec_alloc_frame)) {
    cerr <<  "Failed to load avcodec_alloc_frame" << endl;
    return;
  }

  if (!GetFunction("avcodec_get_context_defaults",  (Function &)Favcodec_get_context_defaults)) {
    cerr <<  "Failed to load  avcodec_get_context_defaults" << endl;
    return;
  }

  if (!GetFunction("avcodec_open",                  (Function &)Favcodec_open)) {
    cerr <<  "Failed to load avcodec_open" << endl;
    return;
  }

  if (!GetFunction("avcodec_close",                 (Function &)Favcodec_close)) {
    cerr <<  "Failed to load avcodec_close" << endl;
    return;
  }

  if (!GetFunction("avcodec_encode_video",          (Function &)Favcodec_encode_video)) {
    cerr <<  "Failed to load avcodec_encode_video" << endl;
    return;
  }

  if (!GetFunction("avcodec_decode_video",          (Function &)Favcodec_decode_video)) {
    cerr <<  "Failed to load avcodec_decode_video" << endl;
    return;
  }

  if (!GetFunction("avcodec_set_print_fn",          (Function &)Favcodec_set_print_fn)) {
    cerr <<  "Failed to load avcodec_set_print_fn" << endl;
    return;
  }
   
  /* must be called before using avcodec lib */
  Favcodec_init();
  
  Favcodec_register_all();
  
  Favcodec_set_print_fn(h263_ffmpeg_printon);

  isLoadedOK = TRUE;
}

FfmpgLink::~FfmpgLink()
{
  PDynaLink::Close();
}

int FfmpgLink::AvcodecOpen(AVCodecContext *ctx, AVCodec *codec)
{
  PWaitAndSignal m(processLock);

  PTRACE(6, "Avcodec open for ctxt " << ::hex << ctx << " codec" << codec << ::dec);
  int res = Favcodec_open(ctx, codec);
  PTRACE(6, "Avcodec open result is " << res);

  return res;
}

AVCodec *FfmpgLink::AvcodecFindDecoderByName(const char *name)
{
  AVCodec *res = Favcodec_find_decoder_by_name(name);
  PTRACE(6, "Found decoder " << *name << " at " << ::hex << res << ::dec);
  return res;
}

AVCodec *FfmpgLink::AvcodecFindEncoderByName(const char *name)
{
  AVCodec *res = Favcodec_find_encoder_by_name(name);
  PTRACE(6, "Found encoder " << *name << " at " << ::hex << res << ::dec);
  return res;
}

AVCodecContext *FfmpgLink::AvcodecAllocContext(void)
{
  AVCodecContext *res = Favcodec_alloc_context();
  PTRACE(6, "Allocated context at " << ::hex << res << ::dec);
  return res;
}

AVFrame *FfmpgLink::AvcodecAllocFrame(void)
{
  AVFrame *res = Favcodec_alloc_frame();
  PTRACE(6, "Allocated frame at " << ::hex << res << ::dec);
  return res;
}

int FfmpgLink::AvcodecClose(AVCodecContext *ctx)
{
  PTRACE(6, "Now close context at " << ::hex << ctx << ::dec);
  return Favcodec_close(ctx);
}

int FfmpgLink::AvcodecDecodeVideo(AVCodecContext *ctx, AVFrame *picture, int *got_picture_ptr, BYTE *buf, int buf_size)
{
  PWaitAndSignal m(processLock);

  PTRACE(6, "Avcodec decode video at " << ::hex << ctx << " frame" << picture 
	 << " buf" << (int)buf << ::dec << "           got picture" << *got_picture_ptr 
	 << " buffer size is" << buf_size);
  int res = Favcodec_decode_video(ctx, picture, got_picture_ptr, buf, buf_size);
  PTRACE(6, "Avcodec decode video of " <<buf_size << " bytes.  result is " << res );

  return res;
}

int FfmpgLink::AvcodecEncodeVideo(AVCodecContext *ctx, BYTE *buf, int buf_size, const AVFrame *pict)
{
  PWaitAndSignal m(processLock);

  PTRACE(6, "Avcodec encode video for ctxt " << ::hex << ctx << " picture" << pict 
	 << " buf" << (int)buf << ::dec << "          buffer size is" << buf_size);
  int res = Favcodec_encode_video(ctx, buf, buf_size, pict);

  PTRACE(6, "Avcodec encode video into " << res << " bytes.");
  return res;
}

void FfmpgLink::AvcodecGetContextDefaults(AVCodecContext *s)
{
  PTRACE(6, "Avcodec open for ctxt " << ::hex << s << ::dec);
  Favcodec_get_context_defaults(s);
}

void FfmpgLink::AvcodecInit(void)
{
  Favcodec_init();
}

void FfmpgLink::AvcodecSetPrintFn(void (*print_fn)(char *))
{
  Favcodec_set_print_fn(print_fn);
}

void FfmpgLink::AFavcodecRegisterAll(void)
{
  Favcodec_register_all();
}





FfmpgLink ff;


static OpalMediaFormat const FFH263_MediaFormat("NonStandard.H.263",
                                              OpalMediaFormat::DefaultVideoSessionID,
                                              RTP_DataFrame::DynamicBase,
                                              FALSE,  // No jitter for video
                                              180000, // bits/sec
                                              2000,   // Not sure of this value!
                                              0,      // No intrinsic time per frame
                                              OpalMediaFormat::VideoTimeUnits);



//////////////////////////////////////////////////////////////////////////////



H323_FFH263Capability::H323_FFH263Capability(unsigned _sqcifMPI,
					     unsigned _qcifMPI,
					     unsigned _cifMPI,
					     unsigned _cif4MPI,
					     unsigned _cif16MPI,
					     unsigned _maxBitRate,
					     unsigned _videoFrameRate)
  :H323NonStandardVideoCapability("H.263 lookalike", (const BYTE *)"NonStandard.H.263", 4, 0, 4)
{
  sqcifMPI = _sqcifMPI;
  qcifMPI = _qcifMPI;
  cifMPI = _cifMPI;
  cif4MPI = _cif4MPI;
  cif16MPI = _cif16MPI;      

  maxBitRate = _maxBitRate;
  videoFrameRate = _videoFrameRate;
}


PObject * H323_FFH263Capability::Clone() const
{
  return new H323_FFH263Capability(*this);
}


PString H323_FFH263Capability::GetFormatName() const
{
  PString ans = "NonStandard.H.263";

  if (qcifMPI > 0)
    ans+= ".QCIF";
  else
    ans+= ".CIF";

  return ans;
}


unsigned H323_FFH263Capability::GetSubType() const
{
  return H245_VideoCapability::e_nonStandard;
}

BOOL H323_FFH263Capability::OnSendingPDU(H245_VideoCapability & cap) const
{
  cap.SetTag(H245_VideoCapability::e_nonStandard);

  return TRUE;
}

BOOL H323_FFH263Capability::OnSendingPDU(H245_VideoMode & pdu) const
{
  pdu.SetTag(H245_VideoMode::e_nonStandard);

  return TRUE;
}


BOOL H323_FFH263Capability::OnReceivedPDU(const H245_VideoCapability & cap)
{
  if (cap.GetTag() != H245_VideoCapability::e_nonStandard)
    return FALSE;

  return TRUE;
}


H323Codec * H323_FFH263Capability::CreateCodec(H323Codec::Direction direction) const
{     
  return new H323_FFH263Codec(direction, sqcifMPI, qcifMPI, cifMPI, cif4MPI, cif16MPI, maxBitRate, videoFrameRate);
}

//////////////////////////////////////////////////////////////////////////////

H323_FFH263Codec::H323_FFH263Codec(Direction dir,
			       unsigned _sqcifMPI,
			       unsigned _qcifMPI,
			       unsigned _cifMPI,
			       unsigned _cif4MPI,
			       unsigned _cif16MPI,
			       unsigned _maxBitRate,
			       unsigned _videoFrameRate)
  : H323VideoCodec(FFH263_MediaFormat, dir)
{
  PTRACE(3, "FFH263\t" << (dir == Encoder ? "En" : "De") 
	 << "coder created. Data rate=" << _maxBitRate
	 << " Frame rate=" << _videoFrameRate);

  bitsSent = 0;

  context = NULL;
  picture = NULL;
  
  PTRACE(3, "FFH263\t" << (dir == Encoder ? "En" : "De") << "coder find"); 

  if (!ff.IsLoaded())
	 return;

  if (dir == Encoder){
    codec = ff.AvcodecFindEncoderByName((char *)"h263p");
  } else {
    codec = ff.AvcodecFindDecoderByName((char *)"h263");
  }

  if (codec == NULL) {   
    PTRACE(1, "FFH263\tCodec not found for FFH263+ " << (dir == Encoder ? "En" : "De") << "coder");
	cerr << "FFH263 Codec not found for FFH263+ " << (dir == Encoder ? "En" : "De") << "coder" << endl;
	exit(0);
  }

  bitRateHighLimit = _maxBitRate;
  if (bitRateHighLimit == 0) {
    PTRACE(3, "FFH263\tData Rate is set to 1000 Kb/sec, as supplied value (0) is invalid");
    bitRateHighLimit = 1000 * 1024;
  }
  
  framesPerSec = _videoFrameRate;
  if (framesPerSec == 0) {
    PTRACE(3, "FFH263\tFrame Rate is set to 25 frames/sec, as supplied value (0) is invalid");
    framesPerSec = 25;
  }

  int shifts = -1;
  if (_sqcifMPI) { 
    shifts = 0;     PTRACE(3, "FFH263\t" << (dir == Encoder ? "En" : "De") << "coder for _sqcifMPI ");
  }
  if (_qcifMPI) {
    shifts = 1;  PTRACE(3, "FFH263\t" << (dir == Encoder ? "En" : "De") << "coder for _qcifMPI"); 
  }
  if (_cifMPI) { 
    shifts = 2; PTRACE(3, "FFH263\t" << (dir == Encoder ? "En" : "De") << "coder for _cifMPI");
  }
  if (_cif4MPI) {
    shifts = 3; PTRACE(3, "FFH263\t" << (dir == Encoder ? "En" : "De") << "coder for _cif4MPI");
  }
  if (_cif16MPI) {
    shifts = 4; PTRACE(3, "FFH263\t" << (dir == Encoder ? "En" : "De") << "coder for _cif16MPI");
  }

  if (shifts < 0) {
    PTRACE(1, "FFH263\tERROR in definition of h263 size");
    return;
  }

  PTRACE(3, "FFH263\t" << (dir == Encoder ? "En" : "De") << "coder created." 
	 << "for a size of " << (88 << shifts) << "x" << (72 << shifts));
  
  Resize(88 << shifts , 72 << shifts); //Fill picture structure, open codec.
  frameNum = 0;
}


H323_FFH263Codec::~H323_FFH263Codec()
{
  PWaitAndSignal mutex1(videoHandlerActive);

  CloseCodec();
}

void H323_FFH263Codec::InitialiseCodec()
{
  if (!ff.IsLoaded())
	 return;

  context = ff.AvcodecAllocContext();
  picture = ff.AvcodecAllocFrame();

  PTRACE(6, "FFH263\tCall avcodec_get_context_defaults");
  ff.AvcodecGetContextDefaults(context);

  if (direction == Encoder) {
    context->max_qdiff= 3; // max q difference between frames
    context->rc_qsquish = 0; // limit by clipping
    context->bit_rate = (bitRateHighLimit * 3) >> 2;
    context->bit_rate_tolerance = bitRateHighLimit  << 3;
    context->rc_min_rate = 0;
    context->rc_max_rate = bitRateHighLimit;    /* resolution must be a multiple of two */

    context->qmin = 2;
    PINDEX effRate = (frameWidth > 200) ? bitRateHighLimit / 2 : bitRateHighLimit;

    if (effRate > 0) {
      context->qmax = 31;    
    }

    if (effRate > 20000) 
      context->qmax = 20;    

    if (effRate > 40000) {
      context->qmax = 10;
    }

#ifdef FRAME_RATE_BASE  
    context->frame_rate = framesPerSec * FRAME_RATE_BASE;
#else
    context->frame_rate = framesPerSec * DEFAULT_FRAME_RATE_BASE;
#endif

    context->rtp_mode = 0;
  } else {    
    //Prepare for decoding a video stream.
    encFrameBuffer.SetSize(0);
    currentFragment = 0;
  }

  int size = frameWidth * frameHeight; 
  picture->data[0] = rawFrameBuffer.GetPointer();
  picture->data[1] = picture->data[0] + size;
  picture->data[2] = picture->data[1] + (size / 4);
  picture->linesize[0] = frameWidth;
  picture->linesize[1] = frameWidth / 2;
  picture->linesize[2] = frameWidth / 2;
}

void H323_FFH263Codec::CloseCodec()
{
  if (!ff.IsLoaded())
	 return;

  PTRACE(6, "FFH263\tClose h263 video " <<(direction == Encoder ? "En" : "De") << "coder" );
  if (context == NULL) 
    return;

  ff.AvcodecClose(context);
}



// This function is called from H323_RTPChannel::Transmit() in channels.cxx
// to grab, display, and compress a video frame into FFH263 packets.
//   1- get another frame if all packets of previous frame have been sent
//   2- get next packet on list and send that one
//   3- render the current frame if all of its packets have been sent
BOOL H323_FFH263Codec::Read(BYTE * /*buffer*/, // pointer to the RTP payload
			  unsigned & length, // returns size of the RTP payload
			  RTP_DataFrame & frame)
{

  if (!ff.IsLoaded())
	 return FALSE;

  PWaitAndSignal mutex1(videoHandlerActive);
  PTRACE(6, "FFH263\tAcquire next packet from FFH263 encoder.");

  if (frameNum == 0) {
    startTime = PTime();
  }
   
  if (rawDataChannel == NULL) {
    length = 0;
    PTRACE(3, "FFH263\tNo channel to connect to video grabber, close down video transmission thread.");
    return FALSE;
  }

  if (!rawDataChannel->IsOpen()) {
     length = 0;
     PTRACE(3, "FFH263\tVideo grabber is not initialised, close down video transmission thread.");
     return FALSE;
  }
  BOOL ok = TRUE;

  if (partialPackets.GetFragmentsRemaining() == 0) {
    // No data is waiting to be read. Go and get some with the read call.

    PINDEX fWidth  = ((PVideoChannel *)rawDataChannel)->GetGrabWidth();
    PINDEX fHeight = ((PVideoChannel *)rawDataChannel)->GetGrabHeight();
    PTRACE(6, "FFH263\tVideo grab size is " << fWidth << "x" << fHeight);
    if (fWidth == 0) {
      PTRACE(1,"FFH263\tVideo grab width is 0 x 0, close down video transmission thread.");
      length=0;
      return FALSE;
    }
    Resize(fWidth, fHeight);

    if (!rawDataChannel->Read(rawFrameBuffer.GetPointer(), rawFrameLen)) {
      PTRACE(3, "FFH263\tFailed to read data from video grabber, close down video transmission thread.");
      return FALSE;   //Read failed, return false.
    }
    frameNum++;  //Increment the number of frames grabbed.

    // If there is a Renderer attached, display the grabbed video.
    if (((PVideoChannel *)rawDataChannel)->IsRenderOpen())
      ok = RenderFrame((const BYTE *)rawFrameBuffer); // use data from grab process
    else
      PTRACE(6, "FFH263\t No renderer open");

    unsigned char *srcPointer = encFrameBuffer.GetPointer(encFrameLen);

#if PTRACING
    PTime encTime;
#endif
    PINDEX out_size =  ff.AvcodecEncodeVideo(context, srcPointer, encFrameLen, picture);
    PTRACE(6, "FFH263\tEncoded " << out_size << " bytes from " << frameWidth << "x" << frameHeight << "  " << 
	   PThread::Current()->GetThreadId() << " in  " << (PTime() - encTime) << " seconds");    
    partialPackets.AppendH263Packet(srcPointer, out_size);
  }

  /* This is a sleazy hack to indicate that this RTP data frame contains
     the non-compliant H.263 RTP payload encoding OpenH323 uses */
  frame.SetExtensionType(263);

  H263Packet *packet = partialPackets.GetNextFragment();
  if (packet == NULL) {
    PTRACE(0, "FFH263\tEncoder internal error - there should outstanding PARTIAL packets at this point.");   
    length = 0;
    return TRUE; //And hope the error condition will fix itself
  }
  
  length = packet->GetSize();
  if (!frame.SetPayloadSize(length + 3)) {
    PTRACE(1, "Internal error in h263 codec, cause writing too big a packet (" << length << ")");
    length = 0;
    return TRUE;
  }

  memcpy(frame.GetPayloadPtr() + 3, packet->GetData(), length);
  delete packet;
  length += 3;

  *(frame.GetPayloadPtr() + 0) = (BYTE)partialPackets.GetFragmentIndex();
  *(frame.GetPayloadPtr() + 1) = (BYTE)partialPackets.GetFragmentsTotal();
  *(frame.GetPayloadPtr() + 2) = (BYTE)((frameWidth > 200) ? 1 : 0);  /*Large or small flag*/

  PTimeInterval timeLastPacket(1000 * bitsSent / bitRateHighLimit);
  PTimeInterval deltaT = PTime() - startTime;
  if (timeLastPacket > deltaT) {
    PTRACE(5, "FFH263\tBit rate throttle, "
	   << bitsSent << " bits sent in " << deltaT
	   << " seconds, max=" << bitRateHighLimit
	   << " require time of " << timeLastPacket
	   << " waiting " << (timeLastPacket - deltaT).GetMilliSeconds() << " milli seconds");

   PThread::Current()->Sleep((timeLastPacket - deltaT));
  } 

  startTime = PTime();
  bitsSent = length << 3;

  if (partialPackets.GetFragmentsRemaining() == 0) 
    frame.SetMarker(TRUE);
  else 
    frame.SetMarker(FALSE);

  return TRUE;
}


BOOL H323_FFH263Codec::Write(const BYTE * /*buffer*/,
                           unsigned length,
                           const RTP_DataFrame & frame,
                           unsigned & written)
{
  if (!ff.IsLoaded())
	 return FALSE;

  PWaitAndSignal mutex1(videoHandlerActive);

  if (rawDataChannel == NULL) 
    return FALSE;

  if (lastSequenceNumber == 1) {
    lastSequenceNumber = frame.GetSequenceNumber();
  } else if ((++lastSequenceNumber) != frame.GetSequenceNumber()) {
    PTRACE(3, "FFH263\tDetected loss of one video packet. Will recover.");
    currentFragment = 0;
    lastSequenceNumber = frame.GetSequenceNumber();
  }

  // always indicate we have written the entire packet
  written = length;

  // get payload
  BYTE * payload    = frame.GetPayloadPtr() + 3;
  PINDEX payloadLen = frame.GetPayloadSize() - 3;

  PINDEX fragIndex  = *(frame.GetPayloadPtr() + 0);
  PINDEX nFragments = *(frame.GetPayloadPtr() + 1);
  PINDEX isLarge    = *(frame.GetPayloadPtr() + 2);

  if (isLarge)
    Resize(352, 288);
  else
    Resize(176, 144);
  
  if (fragIndex == 1) {
    currentFragment = 0;
    encFrameBuffer.SetSize(00);
  }
  
  if (fragIndex == (currentFragment + 1)) {
    PINDEX curSize = encFrameBuffer.GetSize();
    memcpy(encFrameBuffer.GetPointer(curSize + payloadLen) + curSize, payload, payloadLen);
    currentFragment++;
  } else {
    currentFragment = 0;
    encFrameBuffer.SetSize(00);
    PTRACE(6, "FFH263\tError in fragment recovery, index " << fragIndex << " out of turn with " << currentFragment << " nFragments"<< nFragments);
    return TRUE;     //*This is an error, but, just return and hope it recovers .
  }


  if ((nFragments != 1) && (currentFragment != nFragments)) 
    return TRUE;  //*WE are still building the packet up from fragments.

  if (!frame.GetMarker()) 
    return TRUE;

// full frame received, now process it
  int got_picture;
  
  int actualSize = encFrameBuffer.GetSize();
  memset(encFrameBuffer.GetPointer(actualSize + FF_INPUT_BUFFER_PADDING_SIZE) + actualSize, 0, FF_INPUT_BUFFER_PADDING_SIZE);
  
  int decodeLen = ff.AvcodecDecodeVideo(context, picture, &got_picture, encFrameBuffer.GetPointer(), actualSize);
  PTRACE(6, "FFH263\tDecoded " << encFrameBuffer.GetSize() << " byte packet. Image= " 
	 << frameWidth << "x" << frameHeight << "  id=" << 	   PThread::Current()->GetThreadId());
  encFrameBuffer.SetSize(0);
  lastebits = 0;
  currentFragment = 0;
  
  if (decodeLen < 0) {
    PTRACE(1, "FFH263\tError while decoding frame");
    return TRUE;
  }
  
  if (got_picture) {
    /* the picture is allocated by the decoder. no need to free it */
    RenderFrame(picture);
    frameNum++; // increment the number of frames written
  } 

  return TRUE;
}


BOOL H323_FFH263Codec::Resize(int _width, int _height)
{
  if (!ff.IsLoaded())
    return FALSE;

  if ((frameWidth == _width) && (frameHeight == _height)) 
    return TRUE;

  PTRACE(6, "FFH263\t" << (direction == Encoder ? "En" : "De") << "coder resizing to "
	 << _width << "x" << _height << ".");
  
  frameWidth = _width;
  frameHeight = _height;
  
  rawFrameLen    = (_width * _height * 3) / 2;
  rawFrameBuffer.SetSize(rawFrameLen + FF_INPUT_BUFFER_PADDING_SIZE); // input video frame
  memset(rawFrameBuffer.GetPointer() + rawFrameLen, 0, FF_INPUT_BUFFER_PADDING_SIZE);
  encFrameLen = rawFrameLen; // this could be set to some lower value
  //encFrameBuffer.SetSize(encFrameLen); // encoded video frame
  
  if (context != NULL) { 
    if (context->codec != NULL) {
      PTRACE(6, "FFH263\t" << (direction == Encoder ? "En" : "De") << "coder closing because of resize to "
	   << _width << "x" << _height << ".");      
      CloseCodec();
    } 
  }
  InitialiseCodec();

  context->width  = frameWidth;
  context->height = frameHeight;
  
  /* open it */
  if (ff.AvcodecOpen(context, codec) < 0) {
    fprintf(stderr, "could not open codec for FFH263P\n");
    PTRACE(0, "FFH263\tVideo " <<(direction == Encoder ? "En" : "De") << "coder open FAILED");
    return FALSE;
  }

  lastebits = 0;
  return TRUE;
}


/* RenderFrame does two things:
   a) Set size of the display frame. This call happens with every frame.
	 A very small overhead.
   b) Display a frame.
*/

BOOL H323_FFH263Codec::RenderFrame(const void * buffer)
{
  if (rawDataChannel == NULL)
    return TRUE;

  //Now display local image.
  ((PVideoChannel *)rawDataChannel)->SetRenderFrameSize(frameWidth, frameHeight);

  return rawDataChannel->Write(buffer, 0 /*unused parameter*/);
}


BOOL H323_FFH263Codec::RenderFrame(AVFrame *pict)
{
  PINDEX offset = 0;
  for (PINDEX plane = 0; plane < 3; plane ++) {
    unsigned char *src = pict->data[plane];
    PINDEX        wrap = pict->linesize[plane];
    PINDEX        ysize = (plane == 0) ? context->height : context->height >> 1;
    PINDEX        xsize = (plane == 0) ? context->width  : context->width  >> 1;
    for (PINDEX line = 0; line < ysize; line++) {
      memcpy(rawFrameBuffer.GetPointer() + offset, src + (line * wrap), xsize);
      offset += xsize;
    }
  }
  return RenderFrame((const BYTE *)rawFrameBuffer);
}


void H323_FFH263Codec::SetTxQualityLevel(int /*qLevel*/)
{
#if 0
  qualityLevel = PMIN(14, PMAX(qLevel,3));

  lowLimit = PMIN(10, qLevel - 2);
  highLimit = qLevel + 12;

  // If there is no bandwidth limit, update the actual value as well
  if (videoBitRate == 0)
    actualQuality = qualityLevel;
#endif
}


void H323_FFH263Codec::SetBackgroundFill(int /*idle*/)
{
  //  fillLevel = PMIN(99, PMAX(idle,1));
}


void H323_FFH263Codec::OnLostPartialPicture()
{
  PTRACE(3, "FFH263\tLost partial picture message ignored, not implemented");
}


void H323_FFH263Codec::OnLostPicture()
{
  PTRACE(3, "FFH263\tLost picture message ignored, not implemented");
}




//////////////////////////////////////////////////////////////////////
H263Packet::H263Packet(void *newData, int newSize)
{
  size = newSize;
  data = newData;
}

H263Packet::~H263Packet()
{
}



//////////////////////////////////////////////////////////////////////
H263FragmentList::~H263FragmentList()
{
  AllowDeleteObjects();
  RemoveAll();
}

void H263FragmentList::AppendH263Packet(H263Packet *packet)
{
  PINDEX length = packet->GetSize();
  nPackets = (length / 1400) + 1;
  
  PINDEX size = length / nPackets;
  unsigned char *data = (unsigned char *)packet->GetData();

  for (PINDEX i = 0; i < nPackets; i++) {
    PINDEX sendSize = (i == (nPackets - 1)) ? packet->GetSize() - (i * size) : size;
    H263Packet *p = new H263Packet(data + (i * size), sendSize);
    Append(p);
  }
}

void H263FragmentList::AppendH263Packet(unsigned char *data, int size)
{
  if (data == NULL)
    return;

  H263Packet p(data, size);
  AppendH263Packet(&p);
}


H263Packet *H263FragmentList::GetNextFragment()
{
  if (GetSize() > 0) {
    DisallowDeleteObjects();
    H263Packet *answer = (H263Packet *)GetAt(0);
    RemoveAt(0);
    return answer;
  }

  return NULL;
}


PINDEX  H263FragmentList::GetFragmentsRemaining()
{
  return GetSize();
}  

PINDEX H263FragmentList::GetFragmentIndex()
{
  return nPackets - GetSize();
}

PINDEX H263FragmentList::GetFragmentsTotal()
{
  return nPackets;
}
   

#endif // H323_AVCODEC


//////////////////////////////////////////////////////////////////////
