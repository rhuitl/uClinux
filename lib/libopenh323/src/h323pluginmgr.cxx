/*
 * h323plugins.cxx
 *
 * H.323 codec plugins handler
 *
 * Open H323 Library
 *
 * Copyright (C) 2004 Post Increment
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
 * The Initial Developer of the Original Code is Post Increment
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: h323pluginmgr.cxx,v $
 * Revision 1.58  2005/08/05 17:11:03  csoutheren
 * Fixed gcc 4.0.1 warning
 *
 * Revision 1.57  2005/06/27 00:31:19  csoutheren
 * Fixed problem with uninitialised variable when using codec-free capability constructor
 * Fixed mismatch with G.711 codec capability table for plugins
 * Both fixes thanks to Benni Badham
 *
 * Revision 1.56  2005/06/21 06:46:35  csoutheren
 * Add ability to create capabilities without codecs for external RTP interface
 *
 * Revision 1.55  2005/06/07 03:22:24  csoutheren
 * Added patch 1198741 with support for plugin codecs with generic capabilities
 * Added patch 1198754 with support for setting quality level on audio codecs
 * Added patch 1198760 with GSM-AMR codec support
 * Many thanks to Richard van der Hoff for his work
 *
 * Revision 1.54  2005/05/03 12:23:05  csoutheren
 * Unlock connection list when creating connection
 * Remove chance of race condition with H.245 negotiation timer
 * Unregister OpalPluginMediaFormat when instance is destroyed
 * Thank to Paul Cadach
 *
 * Revision 1.53  2005/04/28 03:22:17  csoutheren
 * Fixed problem with toLen not being set n factory-based G.711 routines
 * Thanks to Derek Smithies
 *
 * Revision 1.52  2005/01/04 12:20:12  csoutheren
 * Fixed more problems with global statics
 *
 * Revision 1.51  2005/01/04 08:08:46  csoutheren
 * More changes to implement the new configuration methodology, and also to
 * attack the global static problem
 *
 * Revision 1.50  2005/01/03 14:03:42  csoutheren
 * Added new configure options and ability to disable/enable modules
 *
 * Revision 1.49  2005/01/03 06:26:09  csoutheren
 * Added extensive support for disabling code modules at compile time
 *
 * Revision 1.48  2005/01/03 02:53:22  csoutheren
 * Fixed problem compiling without OpenSSL
 *
 * Revision 1.47  2004/12/20 23:30:21  csoutheren
 * Added plugin support for packet loss concealment frames
 *
 * Revision 1.46  2004/12/08 02:03:59  csoutheren
 * Fixed problem with detection of non-FFH.263
 *
 * Revision 1.45  2004/11/29 06:30:54  csoutheren
 * Added support for wideband codecs
 *
 * Revision 1.44  2004/11/20 22:00:50  csoutheren
 * Added hacks for linker problem
 *
 * Revision 1.43  2004/11/12 06:04:45  csoutheren
 * Changed H235Authentiators to use PFactory
 *
 * Revision 1.42  2004/09/03 08:06:42  csoutheren
 * G.711 codecs are not singleton
 *
 * Revision 1.41  2004/09/03 07:13:47  csoutheren
 * Fixed typo returning wrong value for RTP payload code in factory codecs for G.711
 *
 * Revision 1.40  2004/08/26 11:04:33  csoutheren
 * Fixed factory bootstrap on Linux
 *
 * Revision 1.39  2004/08/26 08:41:33  csoutheren
 * Fixed problem compiling on Linux
 *
 * Revision 1.38  2004/08/26 08:05:04  csoutheren
 * Codecs now appear in abstract factory system
 * Fixed Windows factory bootstrap system (again)
 *
 * Revision 1.37  2004/08/24 14:23:11  csoutheren
 * Fixed problem with plugin codecs using capability compare functions
 *
 * Revision 1.36  2004/08/09 11:11:33  csoutheren
 * Added stupid windows hack to force opalwavfile factories to register
 *
 * Revision 1.35  2004/08/02 23:56:15  csoutheren
 * Fixed problem when using --enable-embeddedgsm
 *
 * Revision 1.34  2004/07/07 08:04:56  csoutheren
 * Added video codecs to default codec list, but H.263 is only loaded if the .so/DLL is found
 *
 * Revision 1.33  2004/07/03 06:51:37  rjongbloed
 * Added PTRACE_PARAM() macro to fix warnings on parameters used in PTRACE
 *  macros only.
 *
 * Revision 1.32  2004/06/30 12:31:16  rjongbloed
 * Rewrite of plug in system to use single global variable for all factories to avoid all sorts
 *   of issues with startup orders and Windows DLL multiple instances.
 *
 * Revision 1.31  2004/06/16 04:00:00  csoutheren
 * Fixed problems with T35 information in plugin codecs
 *
 * Revision 1.30  2004/06/09 13:18:48  csoutheren
 * Fixed compile errors and warnings when --disable-video and --disable-audio
 * used, thanks to Paul Rolland
 *
 * Revision 1.29  2004/06/03 23:20:47  csoutheren
 * Fixed compile problem on some gcc variants
 *
 * Revision 1.28  2004/06/03 13:32:01  csoutheren
 * Renamed INSTANTIATE_FACTORY
 *
 * Revision 1.27  2004/06/03 12:48:35  csoutheren
 * Decomposed PFactory declarations to hopefully avoid problems with DLLs
 *
 * Revision 1.26  2004/06/01 10:29:45  csoutheren
 * Fixed problems on Linux
 *
 * Revision 1.25  2004/06/01 07:30:27  csoutheren
 * Removed accidental cut & paste in new code that removed capabilities
 *
 * Revision 1.24  2004/06/01 05:49:27  csoutheren
 * Added code to cleanup some allocated memory upon shutdown
 *
 * Revision 1.23  2004/05/26 23:44:36  csoutheren
 * Fixed problem with incorrect return value on streamed codec functions
 *
 * Revision 1.22  2004/05/23 12:49:20  rjongbloed
 * Tidied some of the OpalMediaFormat usage after abandoning some previous
 *   code due to MSVC6 compiler bug.
 *
 * Revision 1.21  2004/05/19 07:38:23  csoutheren
 * Changed OpalMediaFormat handling to use abstract factory method functions
 *
 * Revision 1.20  2004/05/18 23:12:24  csoutheren
 * Fixed problem with plugins for predefined formats not appearing in default media format list
 *
 * Revision 1.19  2004/05/18 22:26:28  csoutheren
 * Initial support for embedded codecs
 * Fixed problems with streamed codec support
 * Updates for abstract factory loading methods
 *
 * Revision 1.18  2004/05/18 06:02:30  csoutheren
 * Deferred plugin codec loading until after main has executed by using abstract factory classes
 *
 * Revision 1.17  2004/05/13 12:48:03  rjongbloed
 * Fixed correct usage of the subtle distinction between the capability
 *   name (with {sw} etc) and the media format name.
 *
 * Revision 1.16  2004/05/12 13:41:26  csoutheren
 * Added support for getting lists of media formats from plugin manager
 *
 * Revision 1.15  2004/05/09 14:44:36  csoutheren
 * Added support for streamed plugin audio codecs
 *
 * Revision 1.14  2004/05/09 10:08:36  csoutheren
 * Changed new DecodeFrame to return bytes decoded rather than samples decoded
 * Added support for new DecodeFrame to plugin manager
 *
 * Revision 1.13  2004/05/06 12:54:41  rjongbloed
 * Fixed Clone() functions in plug in capabilities so uses copy constructor and
 *   thus copies all fields and all ancestors fields.
 *   Thanks Gustavo García Bernardo Telefónica R&D
 *
 * Revision 1.12  2004/05/04 03:33:33  csoutheren
 * Added guards against comparing certain kinds of Capabilities
 *
 * Revision 1.11  2004/05/02 08:24:57  rjongbloed
 * Fixed loading of plug ins when multiple plug in class sets used. Especially H.323 codecs.
 *
 * Revision 1.10  2004/04/29 15:04:07  ykiryanov
 * Added #ifndef NO_H323_VIDEO around video codec code
 *
 * Revision 1.9  2004/04/22 22:35:00  csoutheren
 * Fixed mispelling of Guilhem Tardy - my apologies to him
 *
 * Revision 1.8  2004/04/22 14:22:21  csoutheren
 * Added RFC 2190 H.263 code as created by Guilhem Tardy and AliceStreet
 * Many thanks to them for their contributions.
 *
 * Revision 1.7  2004/04/14 08:14:41  csoutheren
 * Changed to use generic plugin manager
 *
 * Revision 1.6  2004/04/09 13:28:38  rjongbloed
 * Fixed conversion of plug ins from OpenH323 to OPAL naming convention.
 *
 * Revision 1.5  2004/04/05 13:33:48  csoutheren
 * Fixed typo in GSM capability creation
 *
 * Revision 1.4  2004/04/04 00:41:09  csoutheren
 * Fixed MSVC compile warning
 *
 * Revision 1.3  2004/04/03 12:17:07  csoutheren
 * Updated plugin changes for RTTI changes and added missing include
 *
 * Revision 1.2  2004/04/03 10:38:25  csoutheren
 * Added in initial cut at codec plugin code. Branches are for wimps :)
 *
 * Revision 1.1.2.1  2004/03/31 11:03:16  csoutheren
 * Initial public version
 *
 * Revision 1.15  2004/02/03 06:14:43  craigs
 * Fixed compile warnings under Linux
 *
 * Revision 1.14  2004/01/28 13:29:55  craigs
 * Fixed compile warning under Linux
 *
 * Revision 1.13  2004/01/27 14:55:46  craigs
 * Implemented static linking of new codecs
 *
 * Revision 1.12  2004/01/25 09:08:15  craigs
 * Removed compile warnings
 *
 * Revision 1.11  2004/01/25 04:38:59  craigs
 * Fixed lengths and other parameters
 *
 * Revision 1.10  2004/01/24 22:26:36  craigs
 * Fixed RTP payload problems
 *
 * Revision 1.9  2004/01/23 05:21:15  craigs
 * Updated for changes to the codec plugin interface
 *
 * Revision 1.8  2004/01/13 03:19:11  craigs
 * Fixed problems on Linux
 *
 * Revision 1.7  2004/01/09 11:27:46  craigs
 * Plugin codec audio now works :)
 *
 * Revision 1.6  2004/01/09 07:32:22  craigs
 * More fixes for capability problems
 *
 * Revision 1.5  2004/01/08 06:36:57  craigs
 * Added creation of media format
 *
 * Revision 1.4  2004/01/06 12:50:04  craigs
 * More plugin fixes
 *
 * Revision 1.3  2004/01/06 10:25:28  craigs
 * Implementation of codec plugins
 *
 * Revision 1.2  2004/01/06 07:05:03  craigs
 * Changed to support plugin codecs
 *
 * Revision 1.1  2004/01/04 13:38:25  craigs
 * Implementation of codec plugins
 *
 *
 */

#ifdef __GNUC__
#pragma implementation "h323pluginmgr.h"
#endif

#include <ptlib.h>
#include <h323.h>
#include <h323pluginmgr.h>
#include <opalplugin.h>
#include <opalwavfile.h>
#include <h323caps.h>
#include <h245.h>
#include <rtp.h>
#include <mediafmt.h>

#ifndef NO_H323_VIDEO
#if H323_RFC2190_AVCODEC
extern BOOL OpenH323_IsRFC2190Loaded();
#endif // H323_RFC2190_AVCODEC
#endif // NO_H323_VIDEO

/////////////////////////////////////////////////////////////////////////////

class OpalPluginCodec : public OpalFactoryCodec {
  PCLASSINFO(OpalPluginCodec, PObject)
  public:
    OpalPluginCodec(PluginCodec_Definition * _codecDefn)
      : codecDefn(_codecDefn)
    { 
      if (codecDefn->createCodec == NULL)
        context = NULL;
      else
        context = (codecDefn->createCodec)(codecDefn);
    }

    ~OpalPluginCodec()
    {
      (codecDefn->destroyCodec)(codecDefn, context);
    }

    const struct PluginCodec_Definition * GetDefinition()
    { return codecDefn; }

    PString GetInputFormat() const
    { return codecDefn->sourceFormat; }

    PString GetOutputFormat() const
    { return codecDefn->destFormat; }

    int Encode(const void * from, unsigned * fromLen, void * to,   unsigned * toLen, unsigned int * flag)
    { return (*codecDefn->codecFunction)(codecDefn, context, from, fromLen, to, toLen, flag); }

    unsigned int GetSampleRate() const
    { return codecDefn->sampleRate; }

    unsigned int GetBitsPerSec() const
    { return codecDefn->bitsPerSec; }

    unsigned int GetFrameTime() const
    { return codecDefn->nsPerFrame; }

    unsigned int GetSamplesPerFrame() const
    { return codecDefn->samplesPerFrame; }

    unsigned int GetBytesPerFrame() const
    { return codecDefn->bytesPerFrame; }

    unsigned int GetRecommendedFramesPerPacket() const
    { return codecDefn->recommendedFramesPerPacket; }

    unsigned int GetMaxFramesPerPacket() const
    { return codecDefn->maxFramesPerPacket; }

    BYTE GetRTPPayload() const
    { return (BYTE)codecDefn->rtpPayload; }

    PString GetSDPFormat() const 
    { return codecDefn->sampleRate; }

  protected:
    PluginCodec_Definition * codecDefn;
    void * context;
};

class OpalPluginCodecFactory : public PFactory<OpalFactoryCodec>
{
  public:
    class Worker : public PFactory<OpalFactoryCodec>::WorkerBase 
    {
      public:
        Worker(const PString & key, PluginCodec_Definition * _codecDefn)
          : PFactory<OpalFactoryCodec>::WorkerBase(TRUE), codecDefn(_codecDefn)
        { PFactory<OpalFactoryCodec>::Register(key, this); }

      protected:
        virtual OpalFactoryCodec * Create(const PString &) const
        { return new OpalPluginCodec(codecDefn); }

        PluginCodec_Definition * codecDefn;
    };
};

/////////////////////////////////////////////////////////////////////////////

#ifndef NO_H323_AUDIO_CODECS

extern "C" {
  unsigned char linear2ulaw(int pcm_val);
  int ulaw2linear(unsigned char u_val);
  unsigned char linear2alaw(int pcm_val);
  int alaw2linear(unsigned char u_val);
};

#define DECLARE_FIXED_CODEC(name, format, bps, frameTime, samples, bytes, fpp, maxfpp, payload, sdp) \
class name##_Base : public OpalFactoryCodec { \
  PCLASSINFO(name##_Base, OpalFactoryCodec) \
  public: \
    name##_Base() \
    { } \
    unsigned int GetSampleRate() const                 { return 8000; } \
    unsigned int GetBitsPerSec() const                 { return bps; } \
    unsigned int GetFrameTime() const                  { return frameTime; } \
    unsigned int GetSamplesPerFrame() const            { return samples; } \
    unsigned int GetBytesPerFrame() const              { return bytes; } \
    unsigned int GetRecommendedFramesPerPacket() const { return fpp; } \
    unsigned int GetMaxFramesPerPacket() const         { return maxfpp; } \
    BYTE GetRTPPayload() const                         { return payload; } \
    PString GetSDPFormat() const                       { return sdp; } \
}; \
class name##_Encoder : public name##_Base { \
  PCLASSINFO(name##_Encoder, name##_Base) \
  public: \
    name##_Encoder() \
    { } \
    virtual PString GetInputFormat() const \
    { return format; }  \
    virtual PString GetOutputFormat() const \
    { return "L16"; }  \
    static PString GetFactoryName() \
    { return PString("L16") + "|" + format; } \
    int Encode(const void * from, unsigned * fromLen, void * to,   unsigned * toLen, unsigned int * flag); \
}; \
class name##_Decoder : public name##_Base { \
PCLASSINFO(name##_Decoder, name##_Base) \
  public: \
    name##_Decoder() \
    { } \
    virtual PString GetInputFormat() const \
    { return "L16"; }  \
    virtual PString GetOutputFormat() const \
    { return format; } \
    static PString GetFactoryName() \
    { return PString(format) + "|" + "L16"; } \
    int Encode(const void * from, unsigned * fromLen, void * to,   unsigned * toLen, unsigned int * flag); \
}; \

DECLARE_FIXED_CODEC(OpalG711ALaw64k, OpalG711ALaw64k, 64000, 30000, 240, 240, 30, 30, RTP_DataFrame::PCMA, "PCMA")

int OpalG711ALaw64k_Encoder::Encode(const void * _from, unsigned * fromLen, void * _to,   unsigned * toLen, unsigned int * )
{
  if (*fromLen/2 > *toLen)
    return 0;

  const short * from = (short *)_from;
  BYTE * to          = (BYTE *)_to;

  unsigned count = *fromLen / 2;
  *toLen         = count;

  while (count-- > 0)
    *to++ = linear2alaw(*from++);

  return 1;
}

int OpalG711ALaw64k_Decoder::Encode(const void * _from, unsigned * fromLen, void * _to,   unsigned * toLen, unsigned int * )
{
  if (*fromLen*2 > *toLen)
    return 0;

  const BYTE * from = (BYTE *)_from;
  short * to        = (short *)_to;

  unsigned count = *fromLen;
  *toLen         = count * 2;

  while (count-- > 0)
    *to++ = (short)alaw2linear(*from++);

  return 1;
}

DECLARE_FIXED_CODEC(OpalG711uLaw64k, OpalG711uLaw64k, 64000, 30000, 240, 240, 30, 30, RTP_DataFrame::PCMU, "PCMU")

int OpalG711uLaw64k_Encoder::Encode(const void * _from, unsigned * fromLen, void * _to,   unsigned * toLen, unsigned int * )
{
  if (*fromLen/2 > *toLen)
    return 0;

  const short * from = (short *)_from;
  BYTE * to          = (BYTE *)_to;

  unsigned count = *fromLen / 2;
  *toLen         = count;

  while (count-- > 0)
    *to++ = linear2ulaw(*from++);

  return 1;
}

int OpalG711uLaw64k_Decoder::Encode(const void * _from, unsigned * fromLen, void * _to,   unsigned * toLen, unsigned int * )
{
  if (*fromLen*2 > *toLen)
    return 0;

  const BYTE * from = (BYTE *)_from;
  short * to        = (short *)_to;

  unsigned count = *fromLen;
  *toLen         = count * 2;

  while (count-- > 0)
    *to++ = (short)ulaw2linear(*from++);

  return 1;
}

#endif // NO_H323_AUDIO_CODECS

template <typename CodecClass>
class OpalFixedCodecFactory : public PFactory<OpalFactoryCodec>
{
  public:
    class Worker : public PFactory<OpalFactoryCodec>::WorkerBase 
    {
      public:
        Worker(const PString & key)
          : PFactory<OpalFactoryCodec>::WorkerBase()
        { PFactory<OpalFactoryCodec>::Register(key, this); }

      protected:
        virtual OpalFactoryCodec * Create(const PString &) const
        { return new CodecClass(); }
    };
};


static PString CreateCodecName(PluginCodec_Definition * codec, BOOL addSW)
{
  PString str;
  if (codec->destFormat != NULL)
    str = codec->destFormat;
  else
    str = PString(codec->descr);
  if (addSW)
    str += "{sw}";
  return str;
}

static PString CreateCodecName(const PString & baseName, BOOL addSW)
{
  PString str(baseName);
  if (addSW)
    str += "{sw}";
  return str;
}

class OpalPluginMediaFormat : public OpalMediaFormat
{
  public:
    friend class H323PluginCodecManager;

    OpalPluginMediaFormat(
      PluginCodec_Definition * _encoderCodec,
      unsigned defaultSessionID,  /// Default session for codec type
      BOOL     needsJitter,   /// Indicate format requires a jitter buffer
      unsigned frameTime,     /// Time for frame in RTP units (if applicable)
      unsigned timeUnits,     /// RTP units for frameTime (if applicable)
      time_t timeStamp        /// timestamp (for versioning)
    )
    : OpalMediaFormat(
      CreateCodecName(_encoderCodec, FALSE),
      defaultSessionID,
      (RTP_DataFrame::PayloadTypes)(((_encoderCodec->flags & PluginCodec_RTPTypeMask) == PluginCodec_RTPTypeDynamic) ? RTP_DataFrame::DynamicBase : _encoderCodec->rtpPayload),
      needsJitter,
      _encoderCodec->bitsPerSec,
      _encoderCodec->bytesPerFrame,
      frameTime,
      timeUnits,
      timeStamp
    )
    , encoderCodec(_encoderCodec)
    {
      // manually register the new singleton type, as we do not have a concrete type
      OpalMediaFormatFactory::Register(*this, this);
    }
    ~OpalPluginMediaFormat()
    {
      OpalMediaFormatFactory::Unregister(*this);
    }
    PluginCodec_Definition * encoderCodec;
};

#ifndef NO_H323_AUDIO_CODECS

static H323Capability * CreateG7231Cap(
  PluginCodec_Definition * encoderCodec, 
  PluginCodec_Definition * decoderCodec,
  int subType
);

static H323Capability * CreateGenericAudioCap(
  PluginCodec_Definition * encoderCodec, 
  PluginCodec_Definition * decoderCodec,
  int subType
);

static H323Capability * CreateNonStandardAudioCap(
  PluginCodec_Definition * encoderCodec, 
  PluginCodec_Definition * decoderCodec,
  int subType
);

static H323Capability * CreateGSMCap(
  PluginCodec_Definition * encoderCodec, 
  PluginCodec_Definition * decoderCodec,
  int subType
);

#endif

#ifndef  NO_H323_VIDEO
#if 0
static H323Capability * CreateH261Cap(
  PluginCodec_Definition * encoderCodec, 
  PluginCodec_Definition * decoderCodec,
  int subType
);
#endif
#endif


/*
//////////////////////////////////////////////////////////////////////////////
//
// Class to auto-register plugin capabilities
//

class H323CodecPluginCapabilityRegistration : public PObject
{
  public:
    H323CodecPluginCapabilityRegistration(
       PluginCodec_Definition * _encoderCodec,
       PluginCodec_Definition * _decoderCodec
    );

    H323Capability * Create(H323EndPoint & ep) const;
  
    static H323Capability * CreateG7231Cap           (H323EndPoint & ep, int subType) const;
    static H323Capability * CreateNonStandardAudioCap(H323EndPoint & ep, int subType) const;
    //H323Capability * CreateNonStandardVideoCap(H323EndPoint & ep, int subType) const;
    static H323Capability * CreateGSMCap             (H323EndPoint & ep, int subType) const;
    static H323Capability * CreateH261Cap            (H323EndPoint & ep, int subType) const;

  protected:
    PluginCodec_Definition * encoderCodec;
    PluginCodec_Definition * decoderCodec;
};

*/

class H323CodecPluginCapabilityMapEntry {
  public:
    int pluginCapType;
    int h323SubType;
    H323Capability * (* createFunc)(PluginCodec_Definition * encoderCodec, PluginCodec_Definition * decoderCodec, int subType);
};

#ifndef NO_H323_AUDIO_CODECS

static H323CodecPluginCapabilityMapEntry audioMaps[] = {
  { PluginCodec_H323Codec_nonStandard,              H245_AudioCapability::e_nonStandard,         &CreateNonStandardAudioCap },
  { PluginCodec_H323AudioCodec_gsmFullRate,	        H245_AudioCapability::e_gsmFullRate,         &CreateGSMCap },
  { PluginCodec_H323AudioCodec_gsmHalfRate,	        H245_AudioCapability::e_gsmHalfRate,         &CreateGSMCap },
  { PluginCodec_H323AudioCodec_gsmEnhancedFullRate, H245_AudioCapability::e_gsmEnhancedFullRate, &CreateGSMCap },
  { PluginCodec_H323AudioCodec_g711Alaw_64k,        H245_AudioCapability::e_g711Alaw64k },
  { PluginCodec_H323AudioCodec_g711Alaw_56k,        H245_AudioCapability::e_g711Alaw56k },
  { PluginCodec_H323AudioCodec_g711Ulaw_64k,        H245_AudioCapability::e_g711Ulaw64k },
  { PluginCodec_H323AudioCodec_g711Ulaw_56k,        H245_AudioCapability::e_g711Ulaw56k },
  { PluginCodec_H323AudioCodec_g7231,               H245_AudioCapability::e_g7231,               &CreateG7231Cap },
  { PluginCodec_H323AudioCodec_g729,                H245_AudioCapability::e_g729 },
  { PluginCodec_H323AudioCodec_g729AnnexA,          H245_AudioCapability::e_g729AnnexA },
  { PluginCodec_H323AudioCodec_g728,                H245_AudioCapability::e_g728 }, 
  { PluginCodec_H323AudioCodec_g722_64k,            H245_AudioCapability::e_g722_64k },
  { PluginCodec_H323AudioCodec_g722_56k,            H245_AudioCapability::e_g722_56k },
  { PluginCodec_H323AudioCodec_g722_48k,            H245_AudioCapability::e_g722_48k },
  { PluginCodec_H323AudioCodec_g729wAnnexB,         H245_AudioCapability::e_g729wAnnexB }, 
  { PluginCodec_H323AudioCodec_g729AnnexAwAnnexB,   H245_AudioCapability::e_g729AnnexAwAnnexB },
  { PluginCodec_H323Codec_generic,                  H245_AudioCapability::e_genericAudioCapability, &CreateGenericAudioCap },

  // not implemented
  //{ PluginCodec_H323AudioCodec_g729Extensions,      H245_AudioCapability::e_g729Extensions,   0 },
  //{ PluginCodec_H323AudioCodec_g7231AnnexC,         H245_AudioCapability::e_g7231AnnexCMode   0 },
  //{ PluginCodec_H323AudioCodec_is11172,             H245_AudioCapability::e_is11172AudioMode, 0 },
  //{ PluginCodec_H323AudioCodec_is13818Audio,        H245_AudioCapability::e_is13818AudioMode, 0 },

  { -1 }
};

#endif

#ifndef  NO_H323_VIDEO

static H323CodecPluginCapabilityMapEntry videoMaps[] = {
  // video codecs
//  { PluginCodec_H323Codec_nonStandard,              H245_VideoCapability::e_nonStandard, &CreateNonStandardVideoCap },
//  { PluginCodec_H323VideoCodec_h261,                H245_VideoCapability::e_h261VideoCapability, &CreateH261Cap },
/*
  PluginCodec_H323VideoCodec_h262,                // not yet implemented
  PluginCodec_H323VideoCodec_h263,                // not yet implemented
  PluginCodec_H323VideoCodec_is11172,             // not yet implemented
*/

  { -1 }
};

#endif  // NO_H323_VIDEO


//////////////////////////////////////////////////////////////////////////////

static int CallCodecControl(PluginCodec_Definition * codec, void * context, const char * name,
                            void * parm = NULL, unsigned int * parmLen = NULL);

//////////////////////////////////////////////////////////////////////////////
//
// Plugin framed audio codec classes
//

#ifndef NO_H323_AUDIO_CODECS

class H323PluginFramedAudioCodec : public H323FramedAudioCodec
{
  PCLASSINFO(H323PluginFramedAudioCodec, H323FramedAudioCodec);
  public:
    H323PluginFramedAudioCodec(const PString & fmtName, Direction direction, PluginCodec_Definition * _codec)
      : H323FramedAudioCodec(fmtName, direction), codec(_codec)
    { if (codec != NULL && codec->createCodec != NULL) context = (*codec->createCodec)(codec); else context = NULL; }

    ~H323PluginFramedAudioCodec()
    { if (codec != NULL && codec->destroyCodec != NULL) (*codec->destroyCodec)(codec, context); }

    BOOL EncodeFrame(
      BYTE * buffer,        /// Buffer into which encoded bytes are placed
      unsigned int & toLen  /// Actual length of encoded data buffer
    )
    {
      if (codec == NULL || direction != Encoder)
        return FALSE;
      unsigned int fromLen = codec->samplesPerFrame*2;
      toLen                = codec->bytesPerFrame;
      unsigned flags = 0;
      return (codec->codecFunction)(codec, context, 
                                 (const unsigned char *)sampleBuffer.GetPointer(), &fromLen,
                                 buffer, &toLen,
                                 &flags) != 0;
    };

    BOOL DecodeFrame(
      const BYTE * buffer,    /// Buffer from which encoded data is found
      unsigned length,        /// Length of encoded data buffer
      unsigned & written,     /// Number of bytes used from data buffer
      unsigned & bytesDecoded /// Number of bytes output from frame
    )
    {
      if (codec == NULL || direction != Decoder)
        return FALSE;
      unsigned flags = 0;
      if ((codec->codecFunction)(codec, context, 
                                 buffer, &length,
                                 (unsigned char *)sampleBuffer.GetPointer(), &bytesDecoded,
                                 &flags) == 0)
        return FALSE;

      written = length;
      return TRUE;
    }

    void DecodeSilenceFrame(
      void * buffer,        /// Buffer from which encoded data is found
      unsigned length       /// Length of encoded data buffer
    )
    { 
      if ((codec->flags & PluginCodec_DecodeSilence) == 0)
        memset(buffer, 0, length); 
      else {
        unsigned flags = PluginCodec_CoderSilenceFrame;
        (codec->codecFunction)(codec, context, 
                                 NULL, NULL,
                                 buffer, &length,
                                 &flags);
      }
    }

    virtual int GetTxQualityLevel() const 
    { int q = 0; unsigned qLen = sizeof(q); CallCodecControl(codec, context, "get_quality", &q, &qLen); return q || 1; }

    virtual void SetTxQualityLevel(int qlevel)
    { unsigned len = sizeof(qlevel); CallCodecControl(codec, context, "set_quality", &qlevel, &len); }

  protected:
    void * context;
    PluginCodec_Definition * codec;
};

//////////////////////////////////////////////////////////////////////////////
//
// Plugin streamed audio codec classes
//

class H323StreamedPluginAudioCodec : public H323StreamedAudioCodec
{
  PCLASSINFO(H323StreamedPluginAudioCodec, H323StreamedAudioCodec);
  public:
    H323StreamedPluginAudioCodec(
      const PString & fmtName, 
      H323Codec::Direction direction, 
      unsigned samplesPerFrame,  /// Number of samples in a frame
      unsigned bits,             /// Bits per sample
      PluginCodec_Definition * _codec
    )
      : H323StreamedAudioCodec(fmtName, direction, samplesPerFrame, bits), codec(_codec)
    { if (codec != NULL && codec->createCodec != NULL) context = (*codec->createCodec)(codec); else context = NULL; }

    ~H323StreamedPluginAudioCodec()
    { if (codec != NULL && codec->destroyCodec != NULL) (*codec->destroyCodec)(codec, context); }

    int Encode(short sample) const
    {
      if (codec == NULL || direction != Encoder)
        return 0;
      unsigned int fromLen = sizeof(sample);
      int to;
      unsigned toLen = sizeof(to);
      unsigned flags = 0;
      (codec->codecFunction)(codec, context, 
                                 (const unsigned char *)&sample, &fromLen,
                                 (unsigned char *)&to, &toLen,
                                 &flags);
      return to;
    }

    short Decode(int sample) const
    {
      if (codec == NULL || direction != Decoder)
        return 0;
      unsigned fromLen = sizeof(sample);
      short to;
      unsigned toLen   = sizeof(to);
      unsigned flags = 0;
      (codec->codecFunction)(codec, context, 
                                 (const unsigned char *)&sample, &fromLen,
                                 (unsigned char *)&to, &toLen,
                                 &flags);
      return to;
    }
    virtual int GetTxQualityLevel() const 
    { int q = 0; unsigned qLen = sizeof(q); CallCodecControl(codec, context, "get_quality", &q, &qLen); return q || 1; }

    virtual void SetTxQualityLevel(int qlevel)
    { unsigned len = sizeof(qlevel); CallCodecControl(codec, context, "set_quality", &qlevel, &len); }

  protected:
    void * context;
    PluginCodec_Definition * codec;
};

#endif //  NO_H323_AUDIO_CODECS

//////////////////////////////////////////////////////////////////////////////
//
// Plugin video codec class
//

#ifndef NO_H323_VIDEO

class H323PluginVideoCodec : public H323VideoCodec
{
  PCLASSINFO(H323PluginVideoCodec, H323VideoCodec);
  public:
    H323PluginVideoCodec(const PString & fmtName, Direction direction, PluginCodec_Definition * _codec)
      : H323VideoCodec(fmtName, direction), codec(_codec)
    { if (codec != NULL && codec->createCodec != NULL) context = (*codec->createCodec)(codec); else context = NULL; }

    ~H323PluginVideoCodec()
    { if (codec != NULL && codec->destroyCodec != NULL) (*codec->destroyCodec)(codec, context); }

    virtual BOOL Read(
      BYTE * /*buffer*/,            /// Buffer of encoded data
      unsigned & /*length*/,        /// Actual length of encoded data buffer
      RTP_DataFrame & /*rtpFrame*/  /// RTP data frame
    )
    {
      return FALSE;
    }

    virtual BOOL Write(
      const BYTE * /*buffer*/,        /// Buffer of encoded data
      unsigned /*length*/,            /// Length of encoded data buffer
      const RTP_DataFrame & /*rtp*/,  /// RTP data frame
      unsigned & /*written*/          /// Number of bytes used from data buffer
    )
    {
      return FALSE;
    }

    virtual unsigned GetFrameRate() const 
    { unsigned rate = 0; unsigned rateLen = sizeof(rate); CallCodecControl(codec, context, "get_frame_rate", &rate, &rateLen); return rate; }

    void SetTxQualityLevel(int qlevel)
    { unsigned len = sizeof(qlevel); CallCodecControl(codec, context, "set_quality", &qlevel, &len); }
 
    void SetTxMinQuality(int qlevel)
    { unsigned len = sizeof(qlevel); CallCodecControl(codec, context, "set_min_quality", &qlevel, &len); }

    void SetTxMaxQuality(int qlevel)
    { unsigned len = sizeof(qlevel); CallCodecControl(codec, context, "set_max_quality", &qlevel, &len); }

    void SetBackgroundFill(int fillLevel)
    { unsigned len = sizeof(fillLevel); CallCodecControl(codec, context, "set_background_fill", &fillLevel, &len); }

    virtual void OnFastUpdatePicture()
    { CallCodecControl(codec, context, "on_fast_update"); }

    virtual void OnLostPartialPicture()
    { CallCodecControl(codec, context, "on_lost_partial"); }

    virtual void OnLostPicture()
    { CallCodecControl(codec, context, "on_lost_picture"); }

  protected:
    void * context;
    PluginCodec_Definition * codec;
};

#endif // NO_H323_VIDEO

//////////////////////////////////////////////////////////////////////////////
//
// Helper class for handling plugin capabilities
//

class H323PluginCapabilityInfo
{
  public:
    H323PluginCapabilityInfo(PluginCodec_Definition * _encoderCodec,
                             PluginCodec_Definition * _decoderCodec);

    H323PluginCapabilityInfo(const PString & _mediaFormat, 
                             const PString & _baseName);

    const PString & GetFormatName() const
    { return capabilityFormatName; }

    H323Codec * CreateCodec(H323Codec::Direction direction) const;

  protected:
    PluginCodec_Definition * encoderCodec;
    PluginCodec_Definition * decoderCodec;
    PString                  capabilityFormatName;
    OpalMediaFormat          mediaFormat;
};

#ifndef NO_H323_AUDIO_CODECS
//////////////////////////////////////////////////////////////////////////////
//
// Class for handling most plugin capabilities
//

class H323PluginCapability : public H323AudioCapability,
                             public H323PluginCapabilityInfo
{
  PCLASSINFO(H323PluginCapability, H323AudioCapability);
  public:
    H323PluginCapability(PluginCodec_Definition * _encoderCodec,
                         PluginCodec_Definition * _decoderCodec,
                         unsigned _pluginSubType)
      : H323AudioCapability(_decoderCodec->maxFramesPerPacket, _encoderCodec->recommendedFramesPerPacket), 
        H323PluginCapabilityInfo(_encoderCodec, _decoderCodec),
        pluginSubType(_pluginSubType)
      { }

    // this constructor is only used when creating a capability without a codec
    H323PluginCapability(const PString & _mediaFormat, const PString & _baseName,
                         unsigned maxFramesPerPacket, unsigned recommendedFramesPerPacket,
                         unsigned _pluginSubType)
      : H323AudioCapability(maxFramesPerPacket, recommendedFramesPerPacket), 
        H323PluginCapabilityInfo(_mediaFormat, _baseName),
        pluginSubType(_pluginSubType)
      { 
        for (PINDEX i = 0; audioMaps[i].pluginCapType >= 0; i++) {
          if (audioMaps[i].pluginCapType == (int)_pluginSubType) { 
            h323subType = audioMaps[i].h323SubType;
            break;
          }
        }
        rtpPayloadType = OpalMediaFormat(_mediaFormat).GetPayloadType();
      }

    virtual PObject * Clone() const
    { return new H323PluginCapability(*this); }

    virtual PString GetFormatName() const
    { return H323PluginCapabilityInfo::GetFormatName();}

    virtual H323Codec * CreateCodec(H323Codec::Direction direction) const
    { return H323PluginCapabilityInfo::CreateCodec(direction); }

    virtual unsigned GetSubType() const
    { return pluginSubType; }

  protected:
    unsigned pluginSubType;
    unsigned h323subType;   // only set if using capability without codec
};
#endif

#ifndef NO_H323_AUDIO_CODECS

//////////////////////////////////////////////////////////////////////////////
//
// Class for handling non standard audio capabilities
//

class H323CodecPluginNonStandardAudioCapability : public H323NonStandardAudioCapability,
                                                  public H323PluginCapabilityInfo
{
  PCLASSINFO(H323CodecPluginNonStandardAudioCapability, H323NonStandardAudioCapability);
  public:
    H323CodecPluginNonStandardAudioCapability(
                                   PluginCodec_Definition * _encoderCodec,
                                   PluginCodec_Definition * _decoderCodec,
                                   H323NonStandardCapabilityInfo::CompareFuncType compareFunc,
                                   const unsigned char * data, unsigned dataLen);

    H323CodecPluginNonStandardAudioCapability(
                                   PluginCodec_Definition * _encoderCodec,
                                   PluginCodec_Definition * _decoderCodec,
                                   const unsigned char * data, unsigned dataLen);

    virtual PObject * Clone() const
    { return new H323CodecPluginNonStandardAudioCapability(*this); }

    virtual PString GetFormatName() const
    { return H323PluginCapabilityInfo::GetFormatName();}

    virtual H323Codec * CreateCodec(H323Codec::Direction direction) const
    { return H323PluginCapabilityInfo::CreateCodec(direction); }
};


//////////////////////////////////////////////////////////////////////////////
//
// Class for handling generic audio capabilities
//

class H323CodecPluginGenericAudioCapability : public H323GenericAudioCapability,
					      public H323PluginCapabilityInfo
{
  PCLASSINFO(H323CodecPluginGenericAudioCapability, H323GenericAudioCapability);
  public:
    H323CodecPluginGenericAudioCapability(
                                   const PluginCodec_Definition * _encoderCodec,
                                   const PluginCodec_Definition * _decoderCodec,
				   const PluginCodec_H323GenericCodecData * data );

    virtual PObject * Clone() const
    {
      return new H323CodecPluginGenericAudioCapability(*this);
    }

    virtual PString GetFormatName() const
    { return H323PluginCapabilityInfo::GetFormatName();}

    virtual H323Codec * CreateCodec(H323Codec::Direction direction) const
    { return H323PluginCapabilityInfo::CreateCodec(direction); }
};

//////////////////////////////////////////////////////////////////////////////
//
// Class for handling G.723.1 codecs
//

class H323PluginG7231Capability : public H323PluginCapability
{
  PCLASSINFO(H323PluginG7231Capability, H323PluginCapability);
  public:
    H323PluginG7231Capability(PluginCodec_Definition * _encoderCodec,
                               PluginCodec_Definition * _decoderCodec,
                               BOOL _annexA = TRUE)
      : H323PluginCapability(_encoderCodec, _decoderCodec, H245_AudioCapability::e_g7231),
        annexA(_annexA)
      { }

    Comparison Compare(const PObject & obj) const
    {
      if (!PIsDescendant(&obj, H323PluginG7231Capability))
        return LessThan;

      Comparison result = H323AudioCapability::Compare(obj);
      if (result != EqualTo)
        return result;

      PINDEX otherAnnexA = ((const H323PluginG7231Capability &)obj).annexA;
      if (annexA < otherAnnexA)
        return LessThan;
      if (annexA > otherAnnexA)
        return GreaterThan;
      return EqualTo;
    }

    virtual PObject * Clone() const
    { 
      return new H323PluginG7231Capability(*this);
    }

    virtual BOOL OnSendingPDU(H245_AudioCapability & cap, unsigned packetSize) const
    {
      cap.SetTag(H245_AudioCapability::e_g7231);
      H245_AudioCapability_g7231 & g7231 = cap;
      g7231.m_maxAl_sduAudioFrames = packetSize;
      g7231.m_silenceSuppression = annexA;
      return TRUE;
    }

    virtual BOOL OnReceivedPDU(const H245_AudioCapability & cap,  unsigned & packetSize)
    {
      if (cap.GetTag() != H245_AudioCapability::e_g7231)
        return FALSE;
      const H245_AudioCapability_g7231 & g7231 = cap;
      packetSize = g7231.m_maxAl_sduAudioFrames;
      annexA = g7231.m_silenceSuppression;
      return TRUE;
    }

  protected:
    BOOL annexA;
};

//////////////////////////////////////////////////////////////////////////////
//
// Class for handling GSM plugin capabilities
//

class H323GSMPluginCapability : public H323PluginCapability
{
  PCLASSINFO(H323GSMPluginCapability, H323PluginCapability);
  public:
    H323GSMPluginCapability(PluginCodec_Definition * _encoderCodec,
                            PluginCodec_Definition * _decoderCodec,
                            int _pluginSubType, int _comfortNoise, int _scrambled)
      : H323PluginCapability(_encoderCodec, _decoderCodec, _pluginSubType),
        comfortNoise(_comfortNoise), scrambled(_scrambled)
    { }

    Comparison Compare(const PObject & obj) const;

    virtual PObject * Clone() const
    {
      return new H323GSMPluginCapability(*this);
    }

    virtual BOOL OnSendingPDU(
      H245_AudioCapability & pdu,  /// PDU to set information on
      unsigned packetSize          /// Packet size to use in capability
    ) const;

    virtual BOOL OnReceivedPDU(
      const H245_AudioCapability & pdu,  /// PDU to get information from
      unsigned & packetSize              /// Packet size to use in capability
    );
  protected:
    int comfortNoise;
    int scrambled;
};

#endif // NO_H323_AUDIO_CODECS

#ifndef  NO_H323_VIDEO

#if 0

//////////////////////////////////////////////////////////////////////////////
//
// Class for handling non standard video capabilities
//

class H323CodecPluginNonStandardVideoCapability : public H323NonStandardVideoCapability,
                                                  public H323PluginCapabilityInfo
{
  PCLASSINFO(H323CodecPluginNonStandardVideoCapability, H323NonStandardVideoCapability);
  public:
    H323CodecPluginNonStandardVideoCapability(
                                   PluginCodec_Definition * _encoderCodec,
                                   PluginCodec_Definition * _decoderCodec,
                                   H323NonStandardCapabilityInfo::CompareFuncType compareFunc);

    H323CodecPluginNonStandardVideoCapability(
                                   PluginCodec_Definition * _encoderCodec,
                                   PluginCodec_Definition * _decoderCodec,
                                   const unsigned char * data, unsigned dataLen);

    virtual PObject * Clone() const
    {
      return new H323CodecPluginNonStandardVideoCapability(*this);
    }

    virtual PString GetFormatName() const
    { return H323PluginCapabilityInfo::GetFormatName();}

    virtual H323Codec * CreateCodec(H323Codec::Direction direction) const
    { return H323PluginCapabilityInfo::CreateCodec(direction); }
};

#endif

//////////////////////////////////////////////////////////////////////////////
//
// Class for handling H.261 plugin capabilities
//

class H323H261PluginCapability : public H323PluginCapability
{
  PCLASSINFO(H323H261PluginCapability, H323PluginCapability);
  public:
    H323H261PluginCapability(PluginCodec_Definition * _encoderCodec,
                             PluginCodec_Definition * _decoderCodec,
                             PluginCodec_H323VideoH261 * capData)
      : H323PluginCapability(_encoderCodec, _decoderCodec, H245_VideoCapability::e_h261VideoCapability),
        qcifMPI(capData->qcifMPI),
        cifMPI(capData->cifMPI),
        temporalSpatialTradeOffCapability(capData->temporalSpatialTradeOffCapability),
        maxBitRate(capData->maxBitRate),
        stillImageTransmission(capData->stillImageTransmission)
    { }

    Comparison Compare(const PObject & obj) const;

    virtual PObject * Clone() const
    { 
      return new H323H261PluginCapability(*this); 
    }

    virtual BOOL OnSendingPDU(
      H245_VideoCapability & pdu  /// PDU to set information on
    ) const;

    virtual BOOL OnSendingPDU(
      H245_VideoMode & pdu
    ) const;

    virtual BOOL OnReceivedPDU(
      const H245_VideoCapability & pdu  /// PDU to get information from
    );

    H323Codec * CreateCodec(H323Codec::Direction direction) const
    { return H323PluginCapabilityInfo::CreateCodec(direction); }

  protected:
    unsigned qcifMPI;                   // 1..4 units 1/29.97 Hz
    unsigned cifMPI;                    // 1..4 units 1/29.97 Hz
    BOOL     temporalSpatialTradeOffCapability;
    unsigned maxBitRate;                // units of 100 bit/s
    BOOL     stillImageTransmission;    // Annex D of H.261
};

/////////////////////////////////////////////////////////////////////////////

#endif //  NO_H323_VIDEO

/////////////////////////////////////////////////////////////////////////////

static int CallCodecControl(PluginCodec_Definition * codec, 
                                       void * context,
                                 const char * name,
                                       void * parm, 
                               unsigned int * parmLen)
{
  PluginCodec_ControlDefn * codecControls = codec->codecControls;
  if (codecControls == NULL)
    return 0;

  while (codecControls->name != NULL) {
    if (strcmp(codecControls->name, name) == 0)
      return (*codecControls->control)(codec, context, name, parm, parmLen);
    codecControls++;
  }

  return 0;
}

/////////////////////////////////////////////////////////////////////////////

class H323StaticPluginCodec
{
  public:
    virtual ~H323StaticPluginCodec() { }
    virtual PluginCodec_GetAPIVersionFunction Get_GetAPIFn() = 0;
    virtual PluginCodec_GetCodecFunction Get_GetCodecFn() = 0;
};


H323PluginCodecManager::H323PluginCodecManager(PPluginManager * _pluginMgr)
 : PPluginModuleManager(PLUGIN_CODEC_GET_CODEC_FN_STR, _pluginMgr)
{
  // instantiate all of the media formats
  {
    OpalMediaFormatFactory::KeyList_T keyList = OpalMediaFormatFactory::GetKeyList();
    OpalMediaFormatFactory::KeyList_T::const_iterator r;
    for (r = keyList.begin(); r != keyList.end(); ++r) {
      OpalMediaFormat * instance = OpalMediaFormatFactory::CreateInstance(*r);
      if (instance == NULL) {
        PTRACE(4, "H323PLUGIN\tCannot instantiate opal media format " << *r);
      } else {
        PTRACE(4, "H323PLUGIN\tCreating media format " << *r);
      }
    }
  }

  // instantiate all of the static codecs
  {
    PFactory<H323StaticPluginCodec>::KeyList_T keyList = PFactory<H323StaticPluginCodec>::GetKeyList();
    PFactory<H323StaticPluginCodec>::KeyList_T::const_iterator r;
    for (r = keyList.begin(); r != keyList.end(); ++r) {
      H323StaticPluginCodec * instance = PFactory<H323StaticPluginCodec>::CreateInstance(*r);
      if (instance == NULL) {
        PTRACE(4, "H323PLUGIN\tCannot instantiate static codec plugin " << *r);
      } else {
        PTRACE(4, "H323PLUGIN\tLoading static codec plugin " << *r);
        RegisterStaticCodec(*r, instance->Get_GetAPIFn(), instance->Get_GetCodecFn());
      }
    }
  }

  // cause the plugin manager to load all dynamic plugins
  pluginMgr->AddNotifier(PCREATE_NOTIFIER(OnLoadModule), TRUE);
}

H323PluginCodecManager::~H323PluginCodecManager()
{
}

void H323PluginCodecManager::OnShutdown()
{
  // unregister the plugin media formats
  OpalMediaFormatFactory::UnregisterAll();

  // unregister the plugin capabilities
  H323CapabilityFactory::UnregisterAll();
}

void H323PluginCodecManager::OnLoadPlugin(PDynaLink & dll, INT code)
{
  PluginCodec_GetCodecFunction getCodecs;
  if (!dll.GetFunction(PString(signatureFunctionName), (PDynaLink::Function &)getCodecs)) {
    PTRACE(3, "H323PLUGIN\tPlugin Codec DLL " << dll.GetName() << " is not a plugin codec");
    return;
  }

  unsigned int count;
  PluginCodec_Definition * codecs = (*getCodecs)(&count, PLUGIN_CODEC_VERSION_WIDEBAND);
  if (codecs == NULL || count == 0) {
    PTRACE(3, "H323PLUGIN\tPlugin Codec DLL " << dll.GetName() << " contains no codec definitions");
    return;
  } 

  PTRACE(3, "H323PLUGIN\tLoading plugin codec " << dll.GetName());

  switch (code) {

    // plugin loaded
    case 0:
      RegisterCodecs(count, codecs);
      break;

    // plugin unloaded
    case 1:
      UnregisterCodecs(count, codecs);
      break;

    default:
      break;
  }
}

void H323PluginCodecManager::RegisterStaticCodec(
      const char * PTRACE_PARAM(name),
      PluginCodec_GetAPIVersionFunction /*getApiVerFn*/,
      PluginCodec_GetCodecFunction getCodecFn)
{
  unsigned int count;
  PluginCodec_Definition * codecs = (*getCodecFn)(&count, PLUGIN_CODEC_VERSION);
  if (codecs == NULL || count == 0) {
    PTRACE(3, "H323PLUGIN\tStatic codec " << name << " contains no codec definitions");
    return;
  } 

  RegisterCodecs(count, codecs);
}

void H323PluginCodecManager::RegisterCodecs(unsigned int count, void * _codecList)
{
  // make sure all non-timestamped codecs have the same concept of "now"
  static time_t codecNow = ::time(NULL);

  PluginCodec_Definition * codecList = (PluginCodec_Definition *)_codecList;
  unsigned i, j ;
  for (i = 0; i < count; i++) {

    PluginCodec_Definition & encoder = codecList[i];

    // for every encoder, we need a decoder
    BOOL found = FALSE;
    BOOL isEncoder = FALSE;
    if (encoder.h323CapabilityType != PluginCodec_H323Codec_undefined &&
         (
           ((encoder.flags & PluginCodec_MediaTypeMask) == PluginCodec_MediaTypeAudio) && 
            strcmp(encoder.sourceFormat, "L16") == 0
         ) ||
         (
           ((encoder.flags & PluginCodec_MediaTypeMask) == PluginCodec_MediaTypeAudioStreamed) && 
            strcmp(encoder.sourceFormat, "L16") == 0
         ) ||
         (
           ((encoder.flags & PluginCodec_MediaTypeMask) == PluginCodec_MediaTypeVideo) && 
           strcmp(encoder.sourceFormat, "YUV") == 0
        )
       ) {
      isEncoder = TRUE;
      for (j = 0; j < count; j++) {

        PluginCodec_Definition & decoder = codecList[j];
        if (
            (decoder.h323CapabilityType == encoder.h323CapabilityType) &&
            ((decoder.flags & PluginCodec_MediaTypeMask) == (encoder.flags & PluginCodec_MediaTypeMask)) &&
            (strcmp(decoder.sourceFormat, encoder.destFormat) == 0) &&
            (strcmp(decoder.destFormat,   encoder.sourceFormat) == 0)
            )
          { 

          // deal with codec having no info, or timestamp in future
          time_t timeStamp = codecList[i].info == NULL ? codecNow : codecList[i].info->timestamp;
          if (timeStamp > codecNow)
            timeStamp = codecNow;

          // create the capability and media format associated with this plugin
          CreateCapabilityAndMediaFormat(&encoder, &decoder);
          found = TRUE;

          PTRACE(2, "H323PLUGIN\tPlugin codec " << encoder.descr << " defined");
          break;
        }
      }
    }
    if (!found && isEncoder) {
      PTRACE(2, "H323PLUGIN\tCannot find decoder for plugin encoder " << encoder.descr);
    }
  }
}

void H323PluginCodecManager::UnregisterCodecs(unsigned int /*count*/, void * /*codec*/)
{
}


PMutex & H323PluginCodecManager::GetMediaFormatMutex()
{
  static PMutex mediaMutex;
  return mediaMutex;
}

void H323PluginCodecManager::AddFormat(OpalMediaFormat * fmt)
{
  PWaitAndSignal m(H323PluginCodecManager::GetMediaFormatMutex());
  H323PluginCodecManager::GetMediaFormatList().Append(fmt);
}

void H323PluginCodecManager::AddFormat(const OpalMediaFormat & fmt)
{
  PWaitAndSignal m(H323PluginCodecManager::GetMediaFormatMutex());
  H323PluginCodecManager::GetMediaFormatList().Append(new OpalMediaFormat(fmt));
}

OpalMediaFormat::List H323PluginCodecManager::GetMediaFormats() 
{
  PWaitAndSignal m(H323PluginCodecManager::GetMediaFormatMutex());
  OpalMediaFormat::List & list = H323PluginCodecManager::GetMediaFormatList();
  OpalMediaFormat::List copy;
  for (PINDEX i = 0; i < list.GetSize(); i++)
    copy.Append(new OpalMediaFormat(list[i]));
  return copy;
}

OpalMediaFormat::List & H323PluginCodecManager::GetMediaFormatList()
{
  static OpalMediaFormat::List mediaFormatList;
  return mediaFormatList;
}


void H323PluginCodecManager::CreateCapabilityAndMediaFormat(
       PluginCodec_Definition * encoderCodec,
       PluginCodec_Definition * decoderCodec
) 
{
  // make sure all non-timestamped codecs have the same concept of "now"
  static time_t mediaNow = time(NULL);

  // deal with codec having no info, or timestamp in future
  time_t timeStamp = encoderCodec->info == NULL ? mediaNow : encoderCodec->info->timestamp;
  if (timeStamp > mediaNow)
    timeStamp = mediaNow;

  unsigned defaultSessionID = 0;
  BOOL jitter = FALSE;
  unsigned frameTime = 0;
  unsigned timeUnits = 0;
  switch (encoderCodec->flags & PluginCodec_MediaTypeMask) {
    case PluginCodec_MediaTypeVideo:
      defaultSessionID = OpalMediaFormat::DefaultVideoSessionID;
      jitter = FALSE;
      break;
    case PluginCodec_MediaTypeAudio:
    case PluginCodec_MediaTypeAudioStreamed:
      defaultSessionID = OpalMediaFormat::DefaultAudioSessionID;
      jitter = TRUE;
      frameTime = (8 * encoderCodec->nsPerFrame) / 1000;
      timeUnits = encoderCodec->sampleRate / 1000; // OpalMediaFormat::AudioTimeUnits;
      break;
    default:
      break;
  }

  // add the media format
  if (defaultSessionID == 0) {
    PTRACE(3, "H323PLUGIN\tCodec DLL provides unknown media format " << (int)(encoderCodec->flags & PluginCodec_MediaTypeMask));
  } else {
    PString fmtName = CreateCodecName(encoderCodec, FALSE);
    OpalMediaFormat existingFormat(fmtName, TRUE);
    if (existingFormat.IsValid()) {
      PTRACE(3, "H323PLUGIN\tMedia format " << fmtName << " already exists");
      H323PluginCodecManager::AddFormat(existingFormat);
    } else {
      PTRACE(3, "H323PLUGIN\tCreating new media format" << fmtName);

      // manually register the new singleton type, as we do not have a concrete type
      OpalPluginMediaFormat * mediaFormat = new OpalPluginMediaFormat(
                                   encoderCodec,
                                   defaultSessionID,
                                   jitter,
                                   frameTime,
                                   timeUnits,
                                   timeStamp);

      // if the codec has been flagged to use a shared RTP payload type, then find a codec with the same SDP name
      // and use that RTP code rather than creating a new one. That prevents codecs (like Speex) from consuming
      // dozens of dynamic RTP types
      if ((encoderCodec->flags & PluginCodec_RTPTypeShared) != 0) {
        PWaitAndSignal m(H323PluginCodecManager::GetMediaFormatMutex());
        OpalMediaFormat::List & list = H323PluginCodecManager::GetMediaFormatList();
        for (PINDEX i = 0; i < list.GetSize(); i++) {
          OpalMediaFormat * opalFmt = &list[i];
          OpalPluginMediaFormat * fmt = dynamic_cast<OpalPluginMediaFormat *>(opalFmt);
          if (
               (encoderCodec->sdpFormat != NULL) &&
               (fmt != NULL) && 
               (fmt->encoderCodec->sdpFormat != NULL) &&
               (strcmp(encoderCodec->sdpFormat, fmt->encoderCodec->sdpFormat) == 0)
              ) {
            mediaFormat->rtpPayloadType = fmt->GetPayloadType();
            break;
          }
        }
      }

      // save the format
      H323PluginCodecManager::AddFormat(mediaFormat);
    }
  }

  // add the capability
  H323CodecPluginCapabilityMapEntry * map = NULL;

  switch (encoderCodec->flags & PluginCodec_MediaTypeMask) {
#ifndef NO_H323_AUDIO_CODECS
    case PluginCodec_MediaTypeAudio:
    case PluginCodec_MediaTypeAudioStreamed:
      map = audioMaps;
      break;
#endif

#ifndef NO_H323_VIDEO
    case PluginCodec_MediaTypeVideo:
      map = videoMaps;
      break;
#endif

    default:
      break;
  }

  if (map == NULL) {
    PTRACE(3, "H323PLUGIN\tCannot create capability for unknown plugin codec media format " << (int)(encoderCodec->flags & PluginCodec_MediaTypeMask));
  } else {
    for (PINDEX i = 0; map[i].pluginCapType >= 0; i++) {
      if (map[i].pluginCapType == encoderCodec->h323CapabilityType) {
        H323Capability * cap = NULL;
        if (map[i].createFunc != NULL)
          cap = (*map[i].createFunc)(encoderCodec, decoderCodec, map[i].h323SubType);
        else
        {
#ifndef NO_H323_AUDIO_CODECS            
          cap = new H323PluginCapability(encoderCodec, decoderCodec, map[i].h323SubType);
#endif
        }

        // manually register the new singleton type, as we do not have a concrete type
        if (cap != NULL)
          H323CapabilityFactory::Register(CreateCodecName(encoderCodec, TRUE), cap);
        break;
      }
    }
  }

  // create the factories for the codecs 
  new OpalPluginCodecFactory::Worker(PString(encoderCodec->sourceFormat) + "|" + encoderCodec->destFormat, encoderCodec);
  new OpalPluginCodecFactory::Worker(PString(decoderCodec->sourceFormat) + "|" + decoderCodec->destFormat, decoderCodec);
}

H323Capability * H323PluginCodecManager::CreateCapability(
          const PString & _mediaFormat, 
          const PString & _baseName,
                 unsigned maxFramesPerPacket, 
                 unsigned recommendedFramesPerPacket,
                 unsigned _pluginSubType
  )
{
#ifndef NO_H323_AUDIO_CODECS
  return new H323PluginCapability(_mediaFormat, _baseName,
                                  maxFramesPerPacket, recommendedFramesPerPacket, _pluginSubType);
#else
  // XXX REALLY BAD! FIXME
  return NULL;
#endif
}

/////////////////////////////////////////////////////////////////////////////



#ifndef NO_H323_AUDIO_CODECS

H323Capability * CreateNonStandardAudioCap(
  PluginCodec_Definition * encoderCodec,  
  PluginCodec_Definition * decoderCodec,
  int /*subType*/) 
{
  PluginCodec_H323NonStandardCodecData * pluginData =  (PluginCodec_H323NonStandardCodecData *)encoderCodec->h323CapabilityData;
  if (pluginData == NULL) {
    return new H323CodecPluginNonStandardAudioCapability(
                             encoderCodec, decoderCodec,
                             (const unsigned char *)encoderCodec->descr, 
                             strlen(encoderCodec->descr));
  }

  else if (pluginData->capabilityMatchFunction != NULL) 
    return new H323CodecPluginNonStandardAudioCapability(encoderCodec, decoderCodec,
                             (H323NonStandardCapabilityInfo::CompareFuncType)pluginData->capabilityMatchFunction,
                             pluginData->data, pluginData->dataLength);
  else
    return new H323CodecPluginNonStandardAudioCapability(
                             encoderCodec, decoderCodec,
                             pluginData->data, pluginData->dataLength);
}

H323Capability *CreateGenericAudioCap(
  PluginCodec_Definition * encoderCodec,  
  PluginCodec_Definition * decoderCodec,
  int /*subType*/) 
{
    PluginCodec_H323GenericCodecData * pluginData = (PluginCodec_H323GenericCodecData *)encoderCodec->h323CapabilityData;

    if(pluginData == NULL ) {
	PTRACE(1, "Generic codec information for codec '"<<encoderCodec->descr<<"' has NULL data field");
	return NULL;
    }
    return new H323CodecPluginGenericAudioCapability(encoderCodec, decoderCodec, pluginData);
}

H323Capability * CreateG7231Cap(
  PluginCodec_Definition * encoderCodec,  
  PluginCodec_Definition * decoderCodec,
  int /*subType*/) 
{
  return new H323PluginG7231Capability(encoderCodec, decoderCodec, decoderCodec->h323CapabilityData != 0);
}


H323Capability * CreateGSMCap(
  PluginCodec_Definition * encoderCodec,  
  PluginCodec_Definition * decoderCodec,
  int subType) 
{
  PluginCodec_H323AudioGSMData * pluginData =  (PluginCodec_H323AudioGSMData *)encoderCodec->h323CapabilityData;
  return new H323GSMPluginCapability(encoderCodec, decoderCodec, subType, pluginData->comfortNoise, pluginData->scrambled);
}

#endif

#ifndef NO_H323_VIDEO

#if 0

H323Capability * CreateNonStandardVideoCap(int /*subType*/) const
{
  PluginCodec_H323NonStandardCodecData * pluginData =  (PluginCodec_H323NonStandardCodecData *)encoderCodec->h323CapabilityData;
  if (pluginData == NULL) {
    return new H323CodecPluginNonStandardVideoCapability(
                             encoderCodec, decoderCodec,
                             (const unsigned char *)encoderCodec->descr, 
                             strlen(encoderCodec->descr));
  }

  else if (pluginData->capabilityMatchFunction != NULL)
    return new H323CodecPluginNonStandardVideoCapability(encoderCodec, decoderCodec,
       (H323NonStandardCapabilityInfo::CompareFuncType)pluginData->capabilityMatchFunction);
  else
    return new H323CodecPluginNonStandardVideoCapability(
                             encoderCodec, decoderCodec,
                             pluginData->data, pluginData->dataLength);
}



H323Capability * CreateH261Cap(
  PluginCodec_Definition * encoderCodec, 
  PluginCodec_Definition * decoderCodec,
  int /*subType*/) 
{
  PluginCodec_H323VideoH261 * pluginData =  (PluginCodec_H323VideoH261 *)encoderCodec->h323CapabilityData;
  return new H323H261PluginCapability(encoderCodec, decoderCodec, pluginData);
}

#endif

#endif // NO_H323_VIDEO

/////////////////////////////////////////////////////////////////////////////

H323Codec * H323PluginCapabilityInfo::CreateCodec(H323Codec::Direction direction) const
{  
  // allow use of this class for external codec capabilities
  if (encoderCodec == NULL || decoderCodec == NULL)
    return NULL;

  PluginCodec_Definition * codec = (direction == H323Codec::Encoder) ? encoderCodec : decoderCodec;

  switch (codec->flags & PluginCodec_MediaTypeMask) {

    case PluginCodec_MediaTypeAudio:
#ifndef NO_H323_AUDIO_CODECS
      PTRACE(3, "H323PLUGIN\tCreating framed audio codec " << mediaFormat << " from plugin");
      return new H323PluginFramedAudioCodec(mediaFormat, direction, codec);
#endif  // NO_H323_AUDIO_CODECS

    case PluginCodec_MediaTypeAudioStreamed:
#ifdef NO_H323_AUDIO_CODECS
      PTRACE(3, "H323PLUGIN\tAudio plugins disabled");
      return NULL;
#else
      {
        PTRACE(3, "H323PLUGIN\tCreating audio codec " << mediaFormat << " from plugin");
        int bitsPerSample = (codec->flags & PluginCodec_BitsPerSampleMask) >> PluginCodec_BitsPerSamplePos;
        if (bitsPerSample == 0)
          bitsPerSample = 16;
        return new H323StreamedPluginAudioCodec(
                                mediaFormat, 
                                direction, 
                                codec->samplesPerFrame,
                                bitsPerSample,
                                codec);
      }
#endif  // NO_H323_AUDIO_CODECS

    case PluginCodec_MediaTypeVideo:
#ifdef NO_H323_VIDEO
      PTRACE(3, "H323PLUGIN\tVideo plugins disabled");
      return NULL;
#else
      if (
           (
             (direction == H323Codec::Encoder) &&
             (
               ((codec->flags & PluginCodec_InputTypeMask) != PluginCodec_InputTypeRaw) ||
               ((codec->flags & PluginCodec_OutputTypeMask) != PluginCodec_OutputTypeRTP)
             )
           )
           ||
           (
             (direction != H323Codec::Encoder) &&
             (
               ((codec->flags & PluginCodec_InputTypeMask) != PluginCodec_InputTypeRTP) ||
               ((codec->flags & PluginCodec_OutputTypeMask) != PluginCodec_OutputTypeRaw)
             )
           )
         ) {
          PTRACE(3, "H323PLUGIN\tVideo codec " << mediaFormat << " has incorrect input/output types");
          return NULL;
      }
      PTRACE(3, "H323PLUGIN\tCreating video codec " << mediaFormat << "from plugin");
      return new H323PluginVideoCodec(mediaFormat, direction, codec);
#endif // NO_H323_VIDEO
    default:
      break;
  }

  PTRACE(3, "H323PLUGIN\tCannot create codec for unknown plugin codec media format " << (int)(codec->flags & PluginCodec_MediaTypeMask));
  return NULL;
}

/////////////////////////////////////////////////////////////////////////////

H323PluginCapabilityInfo::H323PluginCapabilityInfo(PluginCodec_Definition * _encoderCodec,
                                                   PluginCodec_Definition * _decoderCodec)
 : encoderCodec(_encoderCodec),
   decoderCodec(_decoderCodec),
   capabilityFormatName(CreateCodecName(_encoderCodec, TRUE)),
   mediaFormat(CreateCodecName(_encoderCodec, FALSE))
{
}

H323PluginCapabilityInfo::H323PluginCapabilityInfo(const PString & _mediaFormat, const PString & _baseName)
 : encoderCodec(NULL),
   decoderCodec(NULL),
   capabilityFormatName(CreateCodecName(_baseName, TRUE)),
   mediaFormat(_mediaFormat)
{
}

#ifndef NO_H323_AUDIO_CODECS

/////////////////////////////////////////////////////////////////////////////

H323CodecPluginNonStandardAudioCapability::H323CodecPluginNonStandardAudioCapability(
    PluginCodec_Definition * _encoderCodec,
    PluginCodec_Definition * _decoderCodec,
    H323NonStandardCapabilityInfo::CompareFuncType compareFunc,
    const unsigned char * data, unsigned dataLen)
 : H323NonStandardAudioCapability(_decoderCodec->maxFramesPerPacket,
                                  _encoderCodec->maxFramesPerPacket,
                                  compareFunc,
                                  data, dataLen), 
   H323PluginCapabilityInfo(_encoderCodec, _decoderCodec)
{
  PluginCodec_H323NonStandardCodecData * nonStdData = (PluginCodec_H323NonStandardCodecData *)_encoderCodec->h323CapabilityData;
  if (nonStdData->objectId != NULL) {
    oid = PString(nonStdData->objectId);
  } else {
    t35CountryCode   = nonStdData->t35CountryCode;
    t35Extension     = nonStdData->t35Extension;
    manufacturerCode = nonStdData->manufacturerCode;
  }
}

H323CodecPluginNonStandardAudioCapability::H323CodecPluginNonStandardAudioCapability(
    PluginCodec_Definition * _encoderCodec,
    PluginCodec_Definition * _decoderCodec,
    const unsigned char * data, unsigned dataLen)
 : H323NonStandardAudioCapability(_decoderCodec->maxFramesPerPacket,
                                  _encoderCodec->maxFramesPerPacket,
                                  data, dataLen), 
   H323PluginCapabilityInfo(_encoderCodec, _decoderCodec)
{
  PluginCodec_H323NonStandardCodecData * nonStdData = (PluginCodec_H323NonStandardCodecData *)_encoderCodec->h323CapabilityData;
  if (nonStdData->objectId != NULL) {
    oid = PString(nonStdData->objectId);
  } else {
    t35CountryCode   = nonStdData->t35CountryCode;
    t35Extension     = nonStdData->t35Extension;
    manufacturerCode = nonStdData->manufacturerCode;
  }
}

/////////////////////////////////////////////////////////////////////////////

H323CodecPluginGenericAudioCapability::H323CodecPluginGenericAudioCapability(
    const PluginCodec_Definition * _encoderCodec,
    const PluginCodec_Definition * _decoderCodec,
    const PluginCodec_H323GenericCodecData *data )
	: H323GenericAudioCapability(_decoderCodec->maxFramesPerPacket,
				     _encoderCodec->maxFramesPerPacket,
				     data -> standardIdentifier, data -> maxBitRate),
	  H323PluginCapabilityInfo((PluginCodec_Definition *)_encoderCodec,
				   (PluginCodec_Definition *) _decoderCodec)
{
    const PluginCodec_H323GenericParameterDefinition *ptr = data -> params;

    for( unsigned i=0; i < data -> nParameters; i++ ) {
	switch(ptr->type) {
	    case PluginCodec_H323GenericParameterDefinition::PluginCodec_GenericParameter_ShortMin:
	    case PluginCodec_H323GenericParameterDefinition::PluginCodec_GenericParameter_ShortMax:
	    case PluginCodec_H323GenericParameterDefinition::PluginCodec_GenericParameter_LongMin:
	    case PluginCodec_H323GenericParameterDefinition::PluginCodec_GenericParameter_LongMax:
		AddIntegerGenericParameter(ptr->collapsing,ptr->id,ptr->type,
					   ptr->value.integer);
		break;
		
	    case PluginCodec_H323GenericParameterDefinition::PluginCodec_GenericParameter_Logical:
	    case PluginCodec_H323GenericParameterDefinition::PluginCodec_GenericParameter_Bitfield:
	    case PluginCodec_H323GenericParameterDefinition::PluginCodec_GenericParameter_OctetString:
	    case PluginCodec_H323GenericParameterDefinition::PluginCodec_GenericParameter_GenericParameter:
	    default:
		PTRACE(1,"Unsupported Generic parameter type "<< ptr->type
		       << " for generic codec " << _encoderCodec->descr );
		break;
	}
	ptr++;
    }
}

/////////////////////////////////////////////////////////////////////////////

PObject::Comparison H323GSMPluginCapability::Compare(const PObject & obj) const
{
  if (!PIsDescendant(&obj, H323GSMPluginCapability))
    return LessThan;

  Comparison result = H323AudioCapability::Compare(obj);
  if (result != EqualTo)
    return result;

  const H323GSMPluginCapability& other = (const H323GSMPluginCapability&)obj;
  if (scrambled < other.scrambled)
    return LessThan;
  if (comfortNoise < other.comfortNoise)
    return LessThan;
  return EqualTo;
}


BOOL H323GSMPluginCapability::OnSendingPDU(H245_AudioCapability & cap, unsigned packetSize) const
{
  cap.SetTag(pluginSubType);
  H245_GSMAudioCapability & gsm = cap;
  gsm.m_audioUnitSize = packetSize * encoderCodec->bytesPerFrame;
  gsm.m_comfortNoise  = comfortNoise;
  gsm.m_scrambled     = scrambled;

  return TRUE;
}


BOOL H323GSMPluginCapability::OnReceivedPDU(const H245_AudioCapability & cap, unsigned & packetSize)
{
  const H245_GSMAudioCapability & gsm = cap;
  packetSize   = gsm.m_audioUnitSize / encoderCodec->bytesPerFrame;
  if (packetSize == 0)
    packetSize = 1;

  scrambled    = gsm.m_scrambled;
  comfortNoise = gsm.m_comfortNoise;

  return TRUE;
}

/////////////////////////////////////////////////////////////////////////////

#endif   // H323_AUDIO_CODECS

#ifdef H323_VIDEO

/////////////////////////////////////////////////////////////////////////////

PObject::Comparison H323H261PluginCapability::Compare(const PObject & obj) const
{
  if (!PIsDescendant(&obj, H323H261PluginCapability))
    return LessThan;

  Comparison result = H323Capability::Compare(obj);
  if (result != EqualTo)
    return result;

  const H323H261PluginCapability & other = (const H323H261PluginCapability &)obj;

  if (((qcifMPI > 0) && (other.qcifMPI > 0)) ||
      ((cifMPI  > 0) && (other.cifMPI > 0)))
    return EqualTo;

  if (qcifMPI > 0)
    return LessThan;

  return GreaterThan;
}


BOOL H323H261PluginCapability::OnSendingPDU(H245_VideoCapability & cap) const
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
  h261.m_maxBitRate = maxBitRate;
  h261.m_stillImageTransmission = stillImageTransmission;
  return TRUE;
}


BOOL H323H261PluginCapability::OnSendingPDU(H245_VideoMode & pdu) const
{
  pdu.SetTag(H245_VideoMode::e_h261VideoMode);
  H245_H261VideoMode & mode = pdu;
  mode.m_resolution.SetTag(cifMPI > 0 ? H245_H261VideoMode_resolution::e_cif
                                      : H245_H261VideoMode_resolution::e_qcif);
  mode.m_bitRate = maxBitRate;
  mode.m_stillImageTransmission = stillImageTransmission;
  return TRUE;
}

BOOL H323H261PluginCapability::OnReceivedPDU(const H245_VideoCapability & cap)
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

/////////////////////////////////////////////////////////////////////////////

#if 0

H323CodecPluginNonStandardVideoCapability::H323CodecPluginNonStandardVideoCapability(
    PluginCodec_Definition * _encoderCodec,
    PluginCodec_Definition * _decoderCodec,
    H323NonStandardCapabilityInfo::CompareFuncType compareFunc)
 : H323NonStandardVideoCapability(_decoderCodec->maxFramesPerPacket,
                                  _encoderCodec->maxFramesPerPacket,
                                  compareFunc), 
   H323PluginCapabilityInfo(_encoderCodec, _decoderCodec),
{
}

H323CodecPluginNonStandardVideoCapability::H323CodecPluginNonStandardVideoCapability(
    PluginCodec_Definition * _encoderCodec,
    PluginCodec_Definition * _decoderCodec,
    const unsigned char * data, unsigned dataLen)
 : H323NonStandardVideoCapability(_decoderCodec->maxFramesPerPacket,
                                  _encoderCodec->maxFramesPerPacket,
                                  data, dataLen), 
   H323PluginCapabilityInfo(_encoderCodec, _decoderCodec),
{
}

#endif

/////////////////////////////////////////////////////////////////////////////

#endif  // H323_VIDEO

/////////////////////////////////////////////////////////////////////////////

H323DynaLink::H323DynaLink(const char * _baseName, const char * _reason)
  : baseName(_baseName), reason(_reason)
{
  isLoadedOK = FALSE;
}

void H323DynaLink::Load()
{
  PStringArray dirs = PPluginManager::GetPluginDirs();
  PINDEX i;
  for (i = 0; !PDynaLink::IsLoaded() && i < dirs.GetSize(); i++)
    PLoadPluginDirectory<H323DynaLink>(*this, dirs[i]);
  
  if (!PDynaLink::IsLoaded()) {
    cerr << "Cannot find " << baseName << " as required for " << ((reason != NULL) ? reason : " a code module") << "." << endl
         << "This function may appear to be installed, but will not operate correctly." << endl
         << "Please put the file " << baseName << PDynaLink::GetExtension() << " into one of the following directories:" << endl
         << "     " << setfill(',') << dirs << setfill(' ') << endl
         << "This list of directories can be set using the PWLIBPLUGINDIR environment variable." << endl;
    return;
  }
}

BOOL H323DynaLink::LoadPlugin(const PString & filename)
{
  PFilePath fn = filename;
  if (fn.GetTitle() *= "libavcodec")
    return PDynaLink::Open(filename);
  return TRUE;
}

/////////////////////////////////////////////////////////////////////////////

static PAtomicInteger bootStrapCount = 0;

void H323PluginCodecManager::Bootstrap()
{
  if (++bootStrapCount != 1)
    return;

#if defined(H323_AUDIO_CODECS) || defined(H323_VIDEO)
  OpalMediaFormat::List & mediaFormatList = H323PluginCodecManager::GetMediaFormatList();
#endif

#ifndef NO_H323_AUDIO_CODECS

  mediaFormatList.Append(new OpalMediaFormat(OpalG711uLaw));
  mediaFormatList.Append(new OpalMediaFormat(OpalG711ALaw));

  new OpalFixedCodecFactory<OpalG711ALaw64k_Encoder>::Worker(OpalG711ALaw64k_Encoder::GetFactoryName());
  new OpalFixedCodecFactory<OpalG711ALaw64k_Decoder>::Worker(OpalG711ALaw64k_Decoder::GetFactoryName());

  new OpalFixedCodecFactory<OpalG711uLaw64k_Encoder>::Worker(OpalG711uLaw64k_Encoder::GetFactoryName());
  new OpalFixedCodecFactory<OpalG711uLaw64k_Decoder>::Worker(OpalG711uLaw64k_Decoder::GetFactoryName());
#endif

#ifndef NO_H323_VIDEO
  // H.323 require an endpoint to have H.261 if it supports video
  mediaFormatList.Append(new OpalMediaFormat("H.261"));

#if H323_RFC2190_AVCODEC
  // only have H.263 if RFC2190 is loaded
  if (OpenH323_IsRFC2190Loaded())
    mediaFormatList.Append(new OpalMediaFormat("RFC2190 H.263"));
#endif  // H323_RFC2190_AVCODEC
#endif  // NO_H323_VIDEO
}

/////////////////////////////////////////////////////////////////////////////

#define INCLUDE_STATIC_CODEC(name) \
extern "C" { \
extern unsigned int Opal_StaticCodec_##name##_GetAPIVersion(); \
extern struct PluginCodec_Definition * Opal_StaticCodec_##name##_GetCodecs(unsigned *,unsigned); \
}; \
class H323StaticPluginCodec_##name : public H323StaticPluginCodec \
{ \
  public: \
    PluginCodec_GetAPIVersionFunction Get_GetAPIFn() \
    { return &Opal_StaticCodec_##name##_GetAPIVersion; } \
    PluginCodec_GetCodecFunction Get_GetCodecFn() \
    { return &Opal_StaticCodec_##name##_GetCodecs; } \
}; \
static PFactory<H323StaticPluginCodec>::Worker<H323StaticPluginCodec_##name > static##name##CodecFactory( #name ); \

#ifdef H323_EMBEDDED_GSM

INCLUDE_STATIC_CODEC(GSM_0610)

#endif

