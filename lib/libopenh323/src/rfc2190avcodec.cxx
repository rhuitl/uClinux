/*
 * rfc2190avcodec.cxx
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
 * $Log: rfc2190avcodec.cxx,v $
 * Revision 1.18  2006/06/06 08:05:40  csoutheren
 * Make sure maxBitRate is always initialised to a useful value
 *
 * Revision 1.17  2006/03/28 05:15:02  csoutheren
 * Change video codecs to set grabber capture size rather than
 * grabber size setting codec size
 *
 * Revision 1.16  2005/08/20 07:43:05  rjongbloed
 * Fixed compiler warnings
 *
 * Revision 1.15  2005/08/20 07:20:25  rjongbloed
 * Fixed compiler warnings
 *
 * Revision 1.14  2005/01/31 06:19:49  csoutheren
 * Move member variable initialisations to avoid crashes when destroying partially constructed
 *  objects
 *
 * Revision 1.13  2004/08/26 08:05:04  csoutheren
 * Codecs now appear in abstract factory system
 * Fixed Windows factory bootstrap system (again)
 *
 * Revision 1.12  2004/07/19 04:05:31  csoutheren
 * Fixed problems with RFC 2190 under VS.net
 *
 * Revision 1.11  2004/07/07 08:04:57  csoutheren
 * Added video codecs to default codec list, but H.263 is only loaded if the .so/DLL is found
 *
 * Revision 1.10  2004/05/20 02:07:29  csoutheren
 * Use macro to work around MSVC internal compiler errors
 *
 * Revision 1.9  2004/05/19 07:38:24  csoutheren
 * Changed OpalMediaFormat handling to use abstract factory method functions
 *
 * Revision 1.8  2004/05/12 23:18:35  csoutheren
 * Adjusted copyright notices for ffh263 and rfc2190 files
 *
 * Revision 1.7  2004/05/04 03:33:33  csoutheren
 * Added guards against comparing certain kinds of Capabilities
 *
 * Revision 1.6  2004/04/28 23:40:22  csoutheren
 * Fixed compile error on Windows
 *
 * Revision 1.5  2004/04/28 13:44:35  csoutheren
 * Use av_free function to free H.263 contexts rather than assuming free is OK
 * Thanks for Guilhem Tardy for this suggestion
 *
 * Revision 1.4  2004/04/26 10:44:14  csoutheren
 * Included most recent H.263 stubs from Guilhem Tardy
 * This appears to fix the stability problems on transmitting video from Linux
 *
 * Revision 1.3  2004/04/24 00:41:15  rjongbloed
 * Fixed file names in header comment.
 *
 * Revision 1.2  2004/04/22 22:35:01  csoutheren
 * Fixed mispelling of Guilhem Tardy - my apologies to him
 *
 * Revision 1.1  2004/04/22 22:20:35  csoutheren
 * New files for RFC2190 H.263 video codec
 * Added RFC 2190 H.263 code as created by Guilhem Tardy and AliceStreet
 * Many thanks to them for their contributions.
 *
 * Revision 1.7  2003/10/31 00:00:00  Guilhem Tardy
 * Restored RFC2190 compliance.
 *
 * Revision 1.6  2003/10/05 00:00:00  Guilhem Tardy
 * Reintroduce ffmpeg own packet slicing technique (now working better).
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
#pragma implementation "rfc2190avcodec.h"
#endif

#include "rfc2190avcodec.h"

#if H323_RFC2190_AVCODEC

#include "h245.h"
#include "rtp.h"
#include "h323pluginmgr.h"

#define  MSVC_OPENH323 1

extern "C" {
#include <avcodec.h>
extern void avcodec_set_print_fn(void (*print_fn)(char *));
};

//////////////////////////////////////////////////////////////////////////////

static void h263_ffmpeg_printon(char * str)
{
  PTRACE(6, "FFMPEG\t" << str);
  strlen(str); // stop any compiler warning about unused variable
}

//////////////////////////////////////////////////////////////////////////////

class RFC2190_FfmpgLink : public H323DynaLink
{
  PCLASSINFO(RFC2190_FfmpgLink, H323DynaLink)
    
  public:
    RFC2190_FfmpgLink();
    ~RFC2190_FfmpgLink();

    AVCodec *AvcodecFindEncoder(enum CodecID id);
    AVCodec *AvcodecFindDecoder(enum CodecID id);
    AVCodecContext *AvcodecAllocContext(void);
    AVFrame *AvcodecAllocFrame(void);
    int AvcodecOpen(AVCodecContext *ctx, AVCodec *codec);
    int AvcodecClose(AVCodecContext *ctx);
    int AvcodecEncodeVideo(AVCodecContext *ctx, BYTE *buf, int buf_size, const AVFrame *pict);
    int AvcodecDecodeVideo(AVCodecContext *ctx, AVFrame *pict, int *got_picture_ptr, BYTE *buf, int buf_size);
    void AvcodecFree(void * ptr);

    void AvcodecSetPrintFn(void (*print_fn)(char *));

  protected:
    void (*Favcodec_init)(void);
    AVCodec *Favcodec_h263_encoder;
    AVCodec *Favcodec_h263p_encoder;
    AVCodec *Favcodec_h263_decoder;
    void (*Favcodec_register)(AVCodec *format);
    AVCodec *(*Favcodec_find_encoder)(enum CodecID id);
    AVCodec *(*Favcodec_find_decoder)(enum CodecID id);
    AVCodecContext *(*Favcodec_alloc_context)(void);
    void (*Favcodec_free)(void *);
    AVFrame *(*Favcodec_alloc_frame)(void);
    int (*Favcodec_open)(AVCodecContext *ctx, AVCodec *codec);
    int (*Favcodec_close)(AVCodecContext *ctx);
    int (*Favcodec_encode_video)(AVCodecContext *ctx, BYTE *buf, int buf_size, const AVFrame *pict);
    int (*Favcodec_decode_video)(AVCodecContext *ctx, AVFrame *pict, int *got_picture_ptr, BYTE *buf, int buf_size);

    void (*Favcodec_set_print_fn)(void (*print_fn)(char *));
};

static struct { int width; int height; } s_vidFrameSize[] = {
  {    0,    0}, // forbidden
  {  128,   96}, // SQCIF
  {  176,  144}, // QCIF
  {  352,  288}, // CIF
  {  704,  576}, // 4CIF
  { 1408, 1152}, // 16CIF
  {    0,    0}, // reserved
  {    0,    0}, // extended PTYPE
};

//////////////////////////////////////////////////////////////////////////////

#define new PNEW

RFC2190_FfmpgLink::RFC2190_FfmpgLink()
  : H323DynaLink("libavcodec", "RFC2190 H.263 video codec")
{
  Load();
  if (!PDynaLink::IsLoaded())
    return;

  if (!GetFunction("avcodec_init", (Function &)Favcodec_init)) {
    cerr << "Failed to load avcodec_int" << endl;
    return;
  }

  if (!GetFunction("h263_encoder", (Function &)Favcodec_h263_encoder)) {
    cerr << "Failed to load h263_encoder" << endl;
    return;
  }

  if (!GetFunction("h263p_encoder", (Function &)Favcodec_h263p_encoder)) {
    cerr << "Failed to load h263p_encoder" << endl;
    return;
  }

  if (!GetFunction("h263_decoder", (Function &)Favcodec_h263_decoder)) {
    cerr << "Failed to load h263_decoder" << endl;
    return;
  }

  if (!GetFunction("register_avcodec", (Function &)Favcodec_register)) {
    cerr << "Failed to load register_avcodec" << endl;
    return;
  }

  if (!GetFunction("avcodec_find_encoder", (Function &)Favcodec_find_encoder)) {
    cerr << "Failed to load avcodec_find_encoder" << endl;
    return;
  }

  if (!GetFunction("avcodec_find_decoder", (Function &)Favcodec_find_decoder)) {
    cerr << "Failed to load avcodec_find_decoder" << endl;
    return;
  }

  if (!GetFunction("avcodec_alloc_context", (Function &)Favcodec_alloc_context)) {
    cerr << "Failed to load avcodec_alloc_context" << endl;
    return;
  }

  if (!GetFunction("avcodec_alloc_frame", (Function &)Favcodec_alloc_frame)) {
    cerr << "Failed to load avcodec_alloc_frame" << endl;
    return;
  }

  if (!GetFunction("avcodec_open", (Function &)Favcodec_open)) {
    cerr << "Failed to load avcodec_open" << endl;
    return;
  }

  if (!GetFunction("avcodec_close", (Function &)Favcodec_close)) {
    cerr << "Failed to load avcodec_close" << endl;
    return;
  }

  if (!GetFunction("avcodec_encode_video", (Function &)Favcodec_encode_video)) {
    cerr << "Failed to load avcodec_encode_video" << endl;
    return;
  }

  if (!GetFunction("avcodec_decode_video", (Function &)Favcodec_decode_video)) {
    cerr << "Failed to load avcodec_decode_video" << endl;
    return;
  }

  if (!GetFunction("avcodec_set_print_fn", (Function &)Favcodec_set_print_fn)) {
    cerr << "Failed to load avcodec_set_print_fn" << endl;
    return;
  }
   
  if (!GetFunction("av_free", (Function &)Favcodec_free)) {
    cerr << "Failed to load avcodec_close" << endl;
    return;
  }

  // must be called before using avcodec lib
  Favcodec_init();

  // register only the codecs needed (to have smaller code)
  Favcodec_register(Favcodec_h263_encoder);
  Favcodec_register(Favcodec_h263p_encoder);
  Favcodec_register(Favcodec_h263_decoder);
  
  Favcodec_set_print_fn(h263_ffmpeg_printon);

  isLoadedOK = TRUE;

  // instantiate capability here
}

RFC2190_FfmpgLink::~RFC2190_FfmpgLink()
{
  PDynaLink::Close();
}

AVCodec *RFC2190_FfmpgLink::AvcodecFindEncoder(enum CodecID id)
{
  AVCodec *res = Favcodec_find_encoder(id);
  PTRACE_IF(6, res != NULL, "FFLINK\tFound encoder " << res->name << " @ " << ::hex << (int)res << ::dec);
  return res;
}

AVCodec *RFC2190_FfmpgLink::AvcodecFindDecoder(enum CodecID id)
{
  AVCodec *res = Favcodec_find_decoder(id);
  PTRACE_IF(6, res != NULL, "FFLINK\tFound decoder " << res->name << " @ " << ::hex << (int)res << ::dec);
  return res;
}

AVCodecContext *RFC2190_FfmpgLink::AvcodecAllocContext(void)
{
  AVCodecContext *res = Favcodec_alloc_context();
  PTRACE_IF(6, res != NULL, "FFLINK\tAllocated context @ " << ::hex << (int)res << ::dec);
  return res;
}

AVFrame *RFC2190_FfmpgLink::AvcodecAllocFrame(void)
{
  AVFrame *res = Favcodec_alloc_frame();
  PTRACE_IF(6, res != NULL, "FFLINK\tAllocated frame @ " << ::hex << (int)res << ::dec);
  return res;
}

int RFC2190_FfmpgLink::AvcodecOpen(AVCodecContext *ctx, AVCodec *codec)
{
  PWaitAndSignal m(processLock);

  PTRACE(6, "FFLINK\tNow open context @ " << ::hex << (int)ctx << ", codec @ " << (int)codec << ::dec);
  return Favcodec_open(ctx, codec);
}

int RFC2190_FfmpgLink::AvcodecClose(AVCodecContext *ctx)
{
  PTRACE(6, "FFLINK\tNow close context @ " << ::hex << (int)ctx << ::dec);
  return Favcodec_close(ctx);
}

int RFC2190_FfmpgLink::AvcodecEncodeVideo(AVCodecContext *ctx, BYTE *buf, int buf_size, const AVFrame *pict)
{
  PWaitAndSignal m(processLock);

  PTRACE(6, "FFLINK\tNow encode video for ctxt @ " << ::hex << (int)ctx << ", pict @ " << (int)pict
	 << ", buf @ " << (int)buf << ::dec << " (" << buf_size << " bytes)");
  int res = Favcodec_encode_video(ctx, buf, buf_size, pict);

  PTRACE(6, "FFLINK\tEncoded video into " << res << " bytes");
  return res;
}

int RFC2190_FfmpgLink::AvcodecDecodeVideo(AVCodecContext *ctx, AVFrame *pict, int *got_picture_ptr, BYTE *buf, int buf_size)
{
  PWaitAndSignal m(processLock);

  PTRACE(6, "FFLINK\tNow decode video for ctxt @ " << ::hex << (int)ctx << ", pict @ " << (int)pict
	 << ", buf @ " << (int)buf << ::dec << " (" << buf_size << " bytes)");
  int res = Favcodec_decode_video(ctx, pict, got_picture_ptr, buf, buf_size);

  PTRACE(6, "FFLINK\tDecoded video of " << res << " bytes, got_picture=" << *got_picture_ptr);
  return res;
}

void RFC2190_FfmpgLink::AvcodecSetPrintFn(void (*print_fn)(char *))
{
  Favcodec_set_print_fn(print_fn);
}

void RFC2190_FfmpgLink::AvcodecFree(void * ptr)
{
  Favcodec_free(ptr);
}

//////////////////////////////////////////////////////////////////////////////

#define new PNEW

#ifndef NO_H323_VIDEO
namespace PWLibStupidLinkerHacks {
  int rfc2190h263Loader;
};
#endif

RFC2190_FfmpgLink rfc2190_ff;

BOOL OpenH323_IsRFC2190Loaded()
{
  return rfc2190_ff.IsLoaded();
}

char OpalRFC2190H263[] = "RFC2190 H.263";

OPAL_MEDIA_FORMAT_DECLARE(OpalRFC2190H263Format,
        OpalRFC2190H263,
        OpalMediaFormat::DefaultVideoSessionID,
        RTP_DataFrame::H263,
        FALSE,  // No jitter for video
        180000, // bits/sec
        2000,   // Not sure of this value!
        0,      // No intrinsic time per frame
        OpalMediaFormat::VideoTimeUnits,
        0)

//////////////////////////////////////////////////////////////////////////////

H323_RFC2190_H263Capability::H323_RFC2190_H263Capability(unsigned _sqcifMPI,
					     unsigned _qcifMPI,
					     unsigned _cifMPI,
					     unsigned _cif4MPI,
					     unsigned _cif16MPI,
					     unsigned _maxBitRate,
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
  sqcifMPI = (_sqcifMPI>0?_sqcifMPI:-(signed)_slowSqcifMPI);
  qcifMPI = (_qcifMPI>0?_qcifMPI:-(signed)_slowQcifMPI);
  cifMPI = (_cifMPI>0?_cifMPI:-(signed)_slowCifMPI);
  cif4MPI = (_cif4MPI>0?_cif4MPI:-(signed)_slowCif4MPI);
  cif16MPI = (_cif16MPI>0?_cif16MPI:-(signed)_slowCif16MPI);

  maxBitRate = _maxBitRate;

  unrestrictedVector = _unrestrictedVector;
  arithmeticCoding = _arithmeticCoding;
  advancedPrediction = _advancedPrediction;
  pbFrames = _pbFrames;

  temporalSpatialTradeOff = _temporalSpatialTradeOff;

  hrd_B = _hrd_B;
  bppMaxKb = _bppMaxKb;

  errorCompensation = _errorCompensation;
}

PObject * H323_RFC2190_H263Capability::Clone() const
{
  return new H323_RFC2190_H263Capability(*this);
}

PObject::Comparison H323_RFC2190_H263Capability::Compare(const PObject & obj) const
{
  if (!PIsDescendant(&obj, H323_RFC2190_H263Capability))
    return LessThan;

  Comparison result = H323Capability::Compare(obj);
  if (result != EqualTo) 
    return result;

  const H323_RFC2190_H263Capability & other = (const H323_RFC2190_H263Capability &)obj;

  if ((sqcifMPI && other.sqcifMPI) ||
      (qcifMPI && other.qcifMPI) ||
      (cifMPI && other.cifMPI) ||
      (cif4MPI && other.cif4MPI) ||
      (cif16MPI && other.cif16MPI))
    return EqualTo;

  if ((!cif16MPI && other.cif16MPI) ||
      (!cif4MPI && other.cif4MPI) ||
      (!cifMPI && other.cifMPI) ||
      (!qcifMPI && other.qcifMPI))
    return LessThan;

  return GreaterThan;
}

PString H323_RFC2190_H263Capability::GetFormatName() const
{
  PString ret = OpalRFC2190H263;

  if (sqcifMPI)
    ret += "-SQCIF";

  if (qcifMPI)
    ret += "-QCIF";

  if (cifMPI)
    ret += "-CIF";

  if (cif4MPI)
    ret += "-4CIF";

  if (cif16MPI)
    ret += "-16CIF";

  return ret;
}

unsigned H323_RFC2190_H263Capability::GetSubType() const
{
  return H245_VideoCapability::e_h263VideoCapability;
}

BOOL H323_RFC2190_H263Capability::OnSendingPDU(H245_VideoCapability & cap) const
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
  h263.m_maxBitRate = (maxBitRate == 0) ? 8250 : maxBitRate;
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

  h263.m_unrestrictedVector                = FALSE;
  h263.m_arithmeticCoding                  = FALSE;
  h263.m_advancedPrediction                = FALSE;
  h263.m_pbFrames                          = FALSE;
  h263.m_temporalSpatialTradeOffCapability = FALSE;
  h263.m_errorCompensation                 = FALSE;

  return TRUE;
}

BOOL H323_RFC2190_H263Capability::OnSendingPDU(H245_VideoMode & pdu) const
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

BOOL H323_RFC2190_H263Capability::OnReceivedPDU(const H245_VideoCapability & cap)
{
  if (cap.GetTag() != H245_VideoCapability::e_h263VideoCapability)
    return FALSE;

  const H245_H263VideoCapability & h263 = cap;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_sqcifMPI))
    sqcifMPI = h263.m_sqcifMPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowSqcifMPI))
    sqcifMPI = -(signed)h263.m_slowSqcifMPI;
  else
    sqcifMPI = 0;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_qcifMPI))
    qcifMPI = h263.m_qcifMPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowQcifMPI))
    qcifMPI = -(signed)h263.m_slowQcifMPI;
  else
    qcifMPI = 0;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_cifMPI))
    cifMPI = h263.m_cifMPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowCifMPI))
    cifMPI = -(signed)h263.m_slowCifMPI;
  else
    cifMPI = 0;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_cif4MPI))
    cif4MPI = h263.m_cif4MPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowCif4MPI))
    cif4MPI = -(signed)h263.m_slowCif4MPI;
  else
    cif4MPI = 0;
  if (h263.HasOptionalField(H245_H263VideoCapability::e_cif16MPI))
    cif16MPI = h263.m_cif16MPI;
  else if (h263.HasOptionalField(H245_H263VideoCapability::e_slowCif16MPI))
    cif16MPI = -(signed)h263.m_slowCif16MPI;
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

H323Codec * H323_RFC2190_H263Capability::CreateCodec(H323Codec::Direction direction) const
{     
  return new H323_RFC2190_H263Codec(direction, sqcifMPI, qcifMPI, cifMPI, cif4MPI, cif16MPI,
                              maxBitRate, unrestrictedVector, arithmeticCoding, advancedPrediction, pbFrames);
}

//////////////////////////////////////////////////////////////////////

void H263Packet::Store(void *_data, int _data_size, void *_hdr, int _hdr_size)
{
  data = _data;
  data_size = _data_size;
  hdr = _hdr;
  hdr_size = _hdr_size;
}

BOOL H263Packet::Read(unsigned & length, RTP_DataFrame & frame)
{
  length = (unsigned) (hdr_size + data_size);
  if (!frame.SetPayloadSize(length)) {
    PTRACE(1, "H263Pck\tNot enough memory for packet of " << length << " bytes");
    length = 0;
    return FALSE;
  }
  memcpy(frame.GetPayloadPtr(), hdr, hdr_size);
  memcpy(frame.GetPayloadPtr() + hdr_size, data, data_size);
  return TRUE;
}

//////////////////////////////////////////////////////////////////////////////

H323_RFC2190_H263Codec::H323_RFC2190_H263Codec(Direction dir,
			       signed _sqcifMPI,
			       signed _qcifMPI,
			       signed _cifMPI,
			       signed _cif4MPI,
			       signed _cif16MPI,
			       unsigned _maxBitRate,
			       BOOL _unrestrictedVector,
			       BOOL /*_arithmeticCoding*/,
			       BOOL /*_advancedPrediction*/,
			       BOOL /*_pbFrames*/)
  : H323VideoCodec(OpalRFC2190H263, dir)
{
  // set some reasonable values for quality etc
  videoQuality = 10; 
  videoQMin = 4;
  videoQMax = 24;
  frameWidth = frameHeight = 0;
  rtpTimestampDelta = 0;
  lastPacketBits = 0;
  frameNum = 0;
  context = NULL;
  picture = NULL;

  if (!rfc2190_ff.IsLoaded())
    return;

  encodedPackets.DisallowDeleteObjects();
  unusedPackets.DisallowDeleteObjects();

  videoFrameRate[SQCIF] = _sqcifMPI;
  videoFrameRate[QCIF] = _qcifMPI;
  videoFrameRate[CIF] = _cifMPI;
  videoFrameRate[CIF4] = _cif4MPI;
  videoFrameRate[CIF16] = _cif16MPI;

  // all terminals that support H.263 support QCIF (H.323, section 6.2.4)
  if (videoFrameRate[QCIF] == 0) {
    signed vfr = 0;
    if (videoFrameRate[CIF] > 0)
      vfr = videoFrameRate[CIF] * 2;
    else if (videoFrameRate[SQCIF] > 0)
      vfr = videoFrameRate[CIF] / 2;
    if (vfr == 0)
      videoFrameRate[QCIF] = 1;
    else
      videoFrameRate[QCIF] = vfr;
  }

  if (!_cif16MPI &&
      !_cif4MPI &&
      !_cifMPI &&
      !_qcifMPI &&
      !_sqcifMPI) {
    PTRACE(1, "RFC2190H263\tERROR in definition of h263 size");
    return;
  }

  bitRateHighLimit = _maxBitRate;

  unrestrictedVector = _unrestrictedVector;
  arithmeticCoding = FALSE;
  advancedPrediction = FALSE;
  pbFrames = FALSE;
  /* Ffmpeg's H.263(+) codec doesn't support arithmeticCoding, advancedPrediction and pbFrames */

  if (direction == Encoder) {
    if (unrestrictedVector)
      codec = rfc2190_ff.AvcodecFindEncoder(CODEC_ID_H263P);
  else
      codec = rfc2190_ff.AvcodecFindEncoder(CODEC_ID_H263);
  }
  else
    codec = rfc2190_ff.AvcodecFindDecoder(CODEC_ID_H263);

  if (codec == NULL) {
    PTRACE(1, "RFC2190H263\tCodec not found for " << (direction == Encoder ? "En" : "De") << "coder");
    return;
  }

  context = rfc2190_ff.AvcodecAllocContext();
  if (context == NULL) {
    PTRACE(1, "RFC2190H263\tFailed to allocate context for " << (direction == Encoder ? "En" : "De") << "coder");
    return;
  }

  picture = rfc2190_ff.AvcodecAllocFrame();
  if (picture == NULL) {
    PTRACE(1, "RFC2190H263\tFailed to allocate frame for " << (direction == Encoder ? "En" : "De") << "coder");
    return;
  }

  if (direction == Encoder) {
    context->codec = NULL;
  }
  else if (!OpenCodec()) { // decoder will re-initialise context with correct frame size
    PTRACE(1, "RFC2190H263\tFailed to open codec for Decoder");
    return;
  }

  PTRACE(3, "RFC2190H263\t" << (direction == Encoder ? "En" : "De") << "coder created");
}

H323_RFC2190_H263Codec::~H323_RFC2190_H263Codec()
{
  PWaitAndSignal mutex1(videoHandlerActive);

  CloseCodec();

  if (context != NULL)
    rfc2190_ff.AvcodecFree(context);

  if (picture != NULL)
    rfc2190_ff.AvcodecFree(picture);

  encodedPackets.AllowDeleteObjects(TRUE);
  unusedPackets.AllowDeleteObjects(TRUE);
}

BOOL H323_RFC2190_H263Codec::OpenCodec()
{
  if (!rfc2190_ff.IsLoaded())
    return FALSE;

  // avoid copying input/output
  context->flags |= CODEC_FLAG_INPUT_PRESERVED; // we guarantee to preserve input for max_b_frames+1 frames
  context->flags |= CODEC_FLAG_EMU_EDGE; // don't draw edges

  context->width  = frameWidth;
  context->height = frameHeight;

  if (direction == Encoder) {
    int size = frameWidth * frameHeight;
    picture->data[0] = rawFrameBuffer.GetPointer();
    picture->data[1] = picture->data[0] + size;
    picture->data[2] = picture->data[1] + (size / 4);
    picture->linesize[0] = frameWidth;
    picture->linesize[1] = frameWidth / 2;
    picture->linesize[2] = frameWidth / 2;
    picture->quality = (float)videoQuality;

    int bitRate = bitRateHighLimit == 0 ? 1024 * 1024 : bitRateHighLimit;
    context->bit_rate = (bitRate * 3) >> 2; // average bit rate
    context->bit_rate_tolerance = bitRate << 3;
    context->rc_min_rate = 0; // minimum bitrate
    context->rc_max_rate = bitRate; // maximum bitrate
    context->mb_qmin = context->qmin = videoQMin;
    context->mb_qmax = context->qmax = videoQMax;
    context->max_qdiff = 3; // max q difference between frames
    context->rc_qsquish = 0; // limit q by clipping
    context->rc_eq= "tex^qComp"; // rate control equation
    context->qcompress = 0.5; // qscale factor between easy & hard scenes (0.0-1.0)
    context->i_quant_factor = (float)-0.6; // qscale factor between p and i frames
    context->i_quant_offset = (float)0.0; // qscale offset between p and i frames
    // context->b_quant_factor = (float)1.25; // qscale factor between ip and b frames
    // context->b_quant_offset = (float)1.25; // qscale offset between ip and b frames

    if (bitRateHighLimit != 0 && (videoBitRateControlModes & DynamicVideoQuality)) {
      context->flags |= CODEC_FLAG_PASS1;
    } else {
      context->flags |= CODEC_FLAG_QSCALE;
    }

    context->mb_decision = FF_MB_DECISION_SIMPLE; // choose only one MB type at a time
    context->me_method = ME_EPZS;
    context->me_subpel_quality = 8;

    context->frame_rate_base = 1;
    context->frame_rate = framesPerSec;

    context->gop_size = framesPerSec; // about one Intra frame per second

    if (unrestrictedVector) // unrestricted motion vector
      context->flags |= CODEC_FLAG_H263P_UMV;
    else
      context->flags &= ~CODEC_FLAG_H263P_UMV;
    if (advancedPrediction) // advanced prediction
      context->flags |= CODEC_FLAG_4MV;
    else
      context->flags &= ~CODEC_FLAG_4MV;
    context->max_b_frames = pbFrames ? 1 : 0;
    context->flags &= ~CODEC_FLAG_H263P_AIC; // advanced intra coding (not handled by H323_FFH263Capability)

    context->flags |= CODEC_FLAG_RFC2190;

    context->rtp_mode = 1;
    context->rtp_payload_size = 750;
    context->rtp_callback = &H323_RFC2190_H263Codec::RtpCallback;
    context->opaque = this; // used to separate out packets from different encode threads
  } else {
    context->workaround_bugs = 0; // no workaround for buggy H.263 implementations
    context->error_concealment = FF_EC_GUESS_MVS | FF_EC_DEBLOCK;
    context->error_resilience = FF_ER_CAREFULL;
  }

  if (rfc2190_ff.AvcodecOpen(context, codec) < 0) {
    PTRACE(1, "RFC2190H263\tFailed to open codec for " <<(direction == Encoder ? "En" : "De") << "coder");
    return FALSE;
  }

  return TRUE;
}

void H323_RFC2190_H263Codec::CloseCodec()
{
  if (!rfc2190_ff.IsLoaded())
    return;

  if (context != NULL) {
    if (context->codec != NULL) {
      rfc2190_ff.AvcodecClose(context);
      PTRACE(5, "RFC2190H263\tClosed codec for " <<(direction == Encoder ? "En" : "De") << "coder" );
    }
  }
}

// This function is called from H323_RTPChannel::Transmit() in channels.cxx
// to grab, display, and compress a video frame into FFH263 packets.
//   1- get another frame if all packets of previous frame have been sent
//   2- get next packet on list and send that one
//   3- render the current frame if all of its packets have been sent
BOOL H323_RFC2190_H263Codec::Read(BYTE * /*buffer*/, // pointer to the RTP payload
			  unsigned & length, // returns size of the RTP payload
			  RTP_DataFrame & frame)
{
  if (!rfc2190_ff.IsLoaded())
    return FALSE;

  PWaitAndSignal mutex1(videoHandlerActive);
  PTRACE(5, "RFC2190H263\tAcquire next packet from Encoder");

  if (rawDataChannel == NULL) {
    PTRACE(3, "RFC2190H263\tNo channel to grab from, close down video transmission thread");
    length = 0;
    return FALSE;
  }

  if (!rawDataChannel->IsOpen()) {
    PTRACE(3, "RFC2190H263\tVideo grabber is not initialised, close down video transmission thread");
    length = 0;
    return FALSE;
  }

  // If no, data is waiting to be read, then go and get some
  if (encodedPackets.GetSize() == 0) {

    // see if grabber has shutdown
    PINDEX width  = ((PVideoChannel *)rawDataChannel)->GetGrabWidth();
    PINDEX height = ((PVideoChannel *)rawDataChannel)->GetGrabHeight();
    if (width == 0 || height == 0) {
      PTRACE(1,"RFC2190H263\tVideo grab dimension is 0, close down video transmission thread");
      length=0;
      return FALSE;
    }

    // see if grabber size is not matched to required size 
    if ((frameWidth != width) || (frameHeight != height)) {

      // see if grabber size if allowed by codec
      int sizeIndex = GetStdSize(width, height);
      if ((sizeIndex != UnknownStdSize) && (videoFrameRate[sizeIndex] != 0)) {
        PTRACE(5, "RFC2190H263\tVideo grab size " << width << "x" << height << " supported by codec");
      }
      else {
        // find largest supported size
        PINDEX w, h;
        if (videoFrameRate[CIF16] > 0) {
          w = s_vidFrameSize[CIF16].width;
          h = s_vidFrameSize[CIF16].height;
        }
        else if (videoFrameRate[CIF4] > 0) {
          w = s_vidFrameSize[CIF4].width;
          h = s_vidFrameSize[CIF4].height;
        }
        else if (videoFrameRate[CIF] > 0) {
          w = s_vidFrameSize[CIF].width;
          h = s_vidFrameSize[CIF].height;
        }
        else if (videoFrameRate[QCIF] > 0) {
          w = s_vidFrameSize[QCIF].width;
          h = s_vidFrameSize[QCIF].height;
        }
        else if (videoFrameRate[SQCIF] > 0) {
          w = s_vidFrameSize[SQCIF].width;
          h = s_vidFrameSize[SQCIF].height;
        }
        else {
          PTRACE(5, "RFC2190H263\tCannot find a size supported by the codec");
          length=0;
          return FALSE;
        }
        PTRACE(5, "RFC2190H263\tVideo grab size " << width << "x" << height << " changed to supported size " << w << "x" << h);
        width = w;
        height = h;
        ((PVideoChannel *)rawDataChannel)->SetGrabberFrameSize(width, height);
      }

      // resize everything
      if (!Resize(width, height)) {
        PTRACE(3, "RFC2190H263\tFailed to resize to " << width << "x" << height << " - close down video transmission thread");
        length=0;
        return FALSE;
      }
    }

    if (!rawDataChannel->Read(rawFrameBuffer.GetPointer(), rawFrameLen)) {
      PTRACE(3, "RFC2190H263\tFailed to read data from video grabber, close down video transmission thread");
      length=0;
      return FALSE;
    }

    if (frameNum > 0) { // update frame rate
      PTimeInterval deltaTime = PTime() - lastFrameTime;
      int dTms = (int)deltaTime.GetMilliSeconds() + 1; // time freeze workaround, because ...
      context->frame_rate = 1000 / dTms + 1; // ... division by 0
      rtpTimestampDelta = 90 * dTms; // ... NetMeeting requires at least 1ms
    }
    lastFrameTime = PTime();

    frameNum++; // increment number of frames grabbed

    // If there is a Renderer attached, display the grabbed video.
    if (((PVideoChannel *)rawDataChannel)->IsRenderOpen())
      (void)RenderFrame(rawFrameBuffer.GetPointer()); // use data from grab process

#if PTRACING
    PTime encTime;
    int out_size =  
#endif
                   rfc2190_ff.AvcodecEncodeVideo(context, encFrameBuffer.GetPointer(), encFrameLen, picture);
    PTRACE(5, "RFC2190H263\tEncoded " << out_size << " bytes from " << frameWidth << "x" << frameHeight
           << " in " << (PTime() - encTime).GetMilliSeconds() << " ms");
  }
  else {
    rtpTimestampDelta = 0;
  }

  if (encodedPackets.GetSize() == 0) {
    PTRACE(1, "RFC2190H263\tEncoder internal error - there should be outstanding packets at this point");
    length = 0;
    return TRUE; // And hope the error condition will fix itself
  }

  H263Packet *packet = (H263Packet *) encodedPackets.RemoveAt(0);

  if (!packet->Read(length, frame)) {
    PTRACE(1, "RFC2190H263\tEncoder internal error - cause writing too big a packet (" << length << ")");
    length = 0;
    return TRUE; // And hope the error condition will fix itself
  }

  unusedPackets.Append(packet);

  frame.SetMarker(encodedPackets.GetSize() == 0);

  if (bitRateHighLimit != 0 && (videoBitRateControlModes & AdaptivePacketDelay)) {
    PTimeInterval timeout(1000 * lastPacketBits / bitRateHighLimit);
    PTimeInterval deltaTime = PTime() - lastPacketTime;
    if (timeout > deltaTime) {
      PTRACE(7, "RFC2190H263\tBitrate throttle: "
	     << lastPacketBits << " bits (" << (lastPacketBits >> 3) << " bytes) sent in "
	     << deltaTime.GetMilliSeconds() << " ms, max " << bitRateHighLimit
	     << " bps -> " << timeout.GetMilliSeconds() << " ms");
      PThread::Current()->Sleep(timeout - deltaTime);
    }
  }
  else
    PThread::Current()->Sleep(2); // 2 ms interval between packets

  lastPacketTime = PTime();
  lastPacketBits = length << 3;

  PTRACE(5, "RFC2190H263\tSending packet of " << length << " bytes");

  return TRUE;
}

BOOL H323_RFC2190_H263Codec::Write(const BYTE * /*buffer*/,
                           unsigned length,
                           const RTP_DataFrame & frame,
                           unsigned & written)
{
  if (!rfc2190_ff.IsLoaded())
    return FALSE;

  PWaitAndSignal mutex1(videoHandlerActive);

  if (rawDataChannel == NULL) {
    PTRACE(3, "RFC2190H263\tNo channel to render to, close down video reception thread");
    return FALSE;
  }

  if (lastSequenceNumber == 1) {
    lastSequenceNumber = frame.GetSequenceNumber();
  } else if ((++lastSequenceNumber) != frame.GetSequenceNumber()) {
    PTRACE(3, "RFC2190H263\tDetected loss of one video packet");
    lastSequenceNumber = frame.GetSequenceNumber();
  }

  PTRACE(5, "RFC2190H263\tReceived packet of " << frame.GetPayloadSize() << " bytes");

  // always indicate we have written the entire packet
  written = length;

  // get payload
  unsigned char * payload = (unsigned char *) frame.GetPayloadPtr(); // this is after the contrib sources
  int payload_size = frame.GetPayloadSize();

  // decode values from the RTP H263 header
  if (frame.GetPayloadType() == RTP_DataFrame::H263) { // RFC 2190
    context->flags &= ~CODEC_FLAG_RFC2429;
    context->flags |= CODEC_FLAG_RFC2190;
  }
  else { // RFC2429
    context->flags &= ~CODEC_FLAG_RFC2190;
    context->flags |= CODEC_FLAG_RFC2429;
    // not supported
  }

  int got_picture, len;

  len = rfc2190_ff.AvcodecDecodeVideo(context, picture, &got_picture, payload, payload_size);

  if (!frame.GetMarker())
    return TRUE;

  // full frame received, now process it...

  len = rfc2190_ff.AvcodecDecodeVideo(context, picture, &got_picture, NULL, -1);

  if (len < 0) {
    PTRACE(1, "RFC2190H263\tError while decoding frame");
    return TRUE; // And hope the error condition will fix itself
  }
  
  if (got_picture) {
    PTRACE(5, "RFC2190H263\tDecoded frame (" << len << " bytes) into image "
           << context->width << "x" << context->height);
  
    // H.263 could change picture size at any time
    if (context->width == 0 || context->height == 0) {
      PTRACE(1,"RFC2190H263\tImage dimension is 0");
      return TRUE; // And hope the error condition will fix itself
    }

    if (!Resize(context->width, context->height)) {
      PTRACE(3, "RFC2190H263\tFailed to resize, close down video reception thread");
      return FALSE;
    }

    if (!RenderFrame(picture)) {
      PTRACE(1, "RFC2190H263\tError while rendering frame");
      return TRUE; // And hope the error condition will fix itself
    }

    frameNum++;
  }

  return TRUE;
}

void H323_RFC2190_H263Codec::RtpCallback(void *data, int data_size,
                                   void *hdr, int hdr_size, void *priv_data)
{
  H323_RFC2190_H263Codec *c = (H323_RFC2190_H263Codec *) priv_data;
  H263Packet *p = c->unusedPackets.GetSize() > 0 ? (H263Packet *) c->unusedPackets.RemoveAt(0) : new H263Packet();

  p->Store(data, data_size, hdr, hdr_size);
  
  c->encodedPackets.Append(p);
}

BOOL H323_RFC2190_H263Codec::Resize(int _width, int _height)
{
  if (!rfc2190_ff.IsLoaded())
    return FALSE;

  if ((frameWidth == _width) && (frameHeight == _height))
    return TRUE;

  int sizeIndex = GetStdSize(_width, _height);
  if (sizeIndex == UnknownStdSize) {
    PTRACE(3, "RFC2190H263\tCannot resize to " << _width << "x" << _height << " (non-standard format)");
    return FALSE;
  }

  int vFRdiv = (int)videoFrameRate[sizeIndex];
  if (vFRdiv > 0)
    framesPerSec = 90000 / (vFRdiv * 3003) + 1;

  else if (vFRdiv < 0)
    framesPerSec = 1; // actually, less.

  else
  {
    PTRACE(3, "RFC2190H263\tCannot resize to " << _width << "x" << _height << " (capability unsupported)");
    return FALSE;
  }

  PTRACE(4, "RFC2190H263\t" << (direction == Encoder ? "En" : "De")
         << "coder resizing to " << _width << "x" << _height);

  frameWidth = _width;
  frameHeight = _height;

  rawFrameLen    = (_width * _height * 3) / 2;
  rawFrameBuffer.SetSize(rawFrameLen + FF_INPUT_BUFFER_PADDING_SIZE);

  if (direction == Encoder) {
    memset(rawFrameBuffer.GetPointer() + rawFrameLen, 0, FF_INPUT_BUFFER_PADDING_SIZE);

    encFrameLen = rawFrameLen; // this could be set to some lower value
    encFrameBuffer.SetSize(encFrameLen); // encoded video frame

    CloseCodec();
    return OpenCodec();
  }

  return TRUE;
}

/* RenderFrame does two things:
   a) Set size of the display frame. This call happens with every frame.
      A very small overhead.
   b) Display a frame.
*/

BOOL H323_RFC2190_H263Codec::RenderFrame(const void *buffer)
{
  if (rawDataChannel == NULL)
    return TRUE;

  //Now display local image.
  ((PVideoChannel *)rawDataChannel)->SetRenderFrameSize(frameWidth, frameHeight);

  return rawDataChannel->Write(buffer, 0 /*unused parameter*/);
}

BOOL H323_RFC2190_H263Codec::RenderFrame(const AVFrame *pict)
{
  int size = frameWidth * frameHeight;

  if (pict->data[1] == pict->data[0] + size
      && pict->data[2] == pict->data[1] + (size >> 2))
    return RenderFrame(pict->data[0]);

  unsigned char *dst = rawFrameBuffer.GetPointer();
  for (int i=0; i<3; i ++) {
    unsigned char *src = pict->data[i];
    int dst_stride = i ? frameWidth >> 1 : frameWidth;
    int src_stride = pict->linesize[i];
    int h = i ? frameHeight >> 1 : frameHeight;

    if (src_stride==dst_stride) {
      memcpy(dst, src, dst_stride*h);
      dst += dst_stride*h;
    } else {
      while (h--) {
        memcpy(dst, src, dst_stride);
        dst += dst_stride;
        src += src_stride;
      }
    }
  }
  return RenderFrame(rawFrameBuffer.GetPointer());
}

void H323_RFC2190_H263Codec::SetTxQualityLevel(int qlevel)
{
  picture->quality = (float)(videoQuality = PMIN(videoQMax, PMAX(qlevel, videoQMin)));
}

void H323_RFC2190_H263Codec::SetTxMinQuality(int qlevel)
{
  context->mb_qmin = context->qmin = videoQMin = PMIN(31, PMAX(qlevel, 1));

  if (videoQuality < videoQMin)
    picture->quality = (float)(videoQuality = qlevel);
}

void H323_RFC2190_H263Codec::SetTxMaxQuality(int qlevel)
{
  context->mb_qmax = context->qmax = videoQMax = PMIN(31, PMAX(qlevel, 1));

  if (videoQuality > videoQMax)
    picture->quality = (float)(videoQuality = qlevel);
}

void H323_RFC2190_H263Codec::SetBackgroundFill(int /*idle*/)
{
}

void H323_RFC2190_H263Codec::SetVideoMode(unsigned mode)
{
  PTRACE(5,"Set videoBitRateControlModes to " << mode);
        
  videoBitRateControlModes = mode;

#if 0
  if (context->codec != NULL) { // some vars need a reset
    CloseCodec();
    OpenCodec();
  }
#endif
}
    
BOOL H323_RFC2190_H263Codec::SetMaxBitRate(unsigned bitRate)
{
  PTRACE(5,"Set bitRateHighLimit to " << bitRate << " bps");
        
  bitRateHighLimit = bitRate;

#if 0
  if (context->codec != NULL) { // some vars need a reset
    CloseCodec();
    return OpenCodec();
  }
#endif

  return TRUE;
}

void H323_RFC2190_H263Codec::OnVideoTemporalSpatialTradeOff()
{
  PTRACE(3, "RFC2190H263\tOnVideoTemporalSpatialTradeOff message ignored, not implemented");
}

void H323_RFC2190_H263Codec::OnLostPartialPicture()
{
  PTRACE(3, "RFC2190H263\tOnLostPartialPicture message ignored, not implemented");
}

void H323_RFC2190_H263Codec::OnLostPicture()
{
  PTRACE(3, "FFH263\tOnLostPicture message ignored, not implemented");
}

int H323_RFC2190_H263Codec::GetStdSize(int _width, int _height)
{
  int sizeIndex;

  for ( sizeIndex = SQCIF; sizeIndex < NumStdSizes; ++sizeIndex ) {
    if ( s_vidFrameSize[sizeIndex].width == _width && s_vidFrameSize[sizeIndex].height == _height )
      return sizeIndex;
  }

  return UnknownStdSize;
}

int H323_RFC2190_H263Codec::GetStdWidth(StdSize size)
{
  return s_vidFrameSize[size].width;
}

int H323_RFC2190_H263Codec::GetStdHeight(StdSize size)
{
  return s_vidFrameSize[size].height;
}

#endif // H323_AVCODEC

//////////////////////////////////////////////////////////////////////
