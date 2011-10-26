/*
 * Speex Plugin codec for OpenH323/OPAL
 *
 * Copyright (C) 2004 Post Increment, All Rights Reserved
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
 * $Log: speexcodec.cxx,v $
 * Revision 1.18  2005/08/15 01:57:13  csoutheren
 * Removed error/warning on 64 bit platforms
 *
 * Revision 1.17  2005/07/15 10:09:00  rogerhardiman
 * Fix SF bug 1237507. Windows uses malloc.h. Linux and FreeBSD uses stdlib.h
 * Wrap #include with _WIN32 to be consistent with malloc.h in pwlib.
 *
 * Revision 1.16  2004/12/20 23:37:43  csoutheren
 * Added packet loss concealment as per Jean-Marc Valin suggestions
 *
 * Revision 1.15  2004/12/20 23:18:01  csoutheren
 * Added stdlib.h to all plugins to keep FreeBSD happy
 * Thanks to Kevin Oberman
 *
 * Revision 1.14  2004/12/06 13:57:16  csoutheren
 * Fixed cut and paste error with wideband speex codec
 *
 * Revision 1.13  2004/11/29 06:29:02  csoutheren
 * Added support for wideband codec modes
 *
 * Revision 1.12  2004/06/16 05:32:52  csoutheren
 * Removed non-working codecs
 *
 * Revision 1.11  2004/06/16 04:35:50  csoutheren
 * Cleanup and add extra tables
 *
 * Revision 1.10  2004/06/16 04:21:05  csoutheren
 * Added rest of supported Speex codecs
 *
 * Revision 1.9  2004/06/16 03:57:58  csoutheren
 * Fixed strings
 *
 * Revision 1.8  2004/06/16 03:33:03  csoutheren
 * Initial support for ACM Speex
 *
 * Revision 1.7  2004/05/13 10:35:09  csoutheren
 * Fixed bit rates and bytes per frame for each codec
 *
 * Revision 1.6  2004/05/12 12:32:44  csoutheren
 * More name fixes
 *
 * Revision 1.5  2004/05/12 11:27:04  csoutheren
 * Changed codec name to match embedded codec
 *
 * Revision 1.4  2004/04/09 12:24:18  csoutheren
 * Renamed h323plugin.h to opalplugin.h, and modified everything else
 * as required
 *
 * Revision 1.3  2004/04/04 12:57:49  csoutheren
 * Updated Makefiles and fixed Linux problems
 *
 * Revision 1.2  2004/04/04 12:44:18  csoutheren
 * Added file headers
 *
 */

#include <opalplugin.h>

extern "C" {
PLUGIN_CODEC_IMPLEMENT("Speex")
};

#include <stdlib.h>
#ifdef _WIN32
#include <malloc.h>
#endif
#include <string.h>

#include "libspeex/speex.h" 

#define NARROW_SAMPLES_PER_FRAME       160
#define WIDE_SAMPLES_PER_FRAME         320

#define NARROW_NS_PER_FRAME            20000
#define WIDE_NS_PER_FRAME              20000

const float MaxSampleValue   = 32767.0;
const float MinSampleValue   = -32767.0;

struct PluginSpeexContext {
  struct SpeexBits * bits;
  void      * coderState;
  unsigned  encoderFrameSize;
};

/////////////////////////////////////////////////////////////////////////////

static void * create_encoder(const struct PluginCodec_Definition * codec)
{
  int mode = (int)(long)(codec->userData);

  struct PluginSpeexContext * context = new PluginSpeexContext;
  context->bits = new SpeexBits;
  speex_bits_init(context->bits);

  if (codec->sampleRate == 16000)
    context->coderState = speex_encoder_init(&speex_wb_mode);
  else
    context->coderState = speex_encoder_init(&speex_nb_mode);

  speex_encoder_ctl(context->coderState, SPEEX_GET_FRAME_SIZE, &context->encoderFrameSize);
  speex_encoder_ctl(context->coderState, SPEEX_SET_QUALITY,    &mode);

  return context;
}

static int codec_encoder(const struct PluginCodec_Definition * codec, 
                                           void * _context,
                                     const void * from, 
                                       unsigned * fromLen,
                                           void * to,         
                                       unsigned * toLen,
                                   unsigned int * flag)
{
  PluginSpeexContext * context = (PluginSpeexContext *)_context;

  if (*fromLen != codec->samplesPerFrame*2)
    return 0;

  short * sampleBuffer = (short *)from;

  // convert PCM to float
  float floatData[WIDE_SAMPLES_PER_FRAME];
  int i;
  for (i = 0; i < codec->samplesPerFrame; i++)
    floatData[i] = sampleBuffer[i];

  // encode PCM data in sampleBuffer to buffer
  speex_bits_reset(context->bits); 
  speex_encode(context->coderState, floatData, context->bits); 

  *toLen = speex_bits_write(context->bits, (char *)to, context->encoderFrameSize); 

  return 1; 
}

static void destroy_encoder(const struct PluginCodec_Definition * codec, void * _context)
{
  PluginSpeexContext * context = (PluginSpeexContext *)_context;

  speex_bits_destroy(context->bits);
  free(context->bits);

  speex_encoder_destroy(context->coderState); 
  free(context);
}

static void * create_decoder(const struct PluginCodec_Definition * codec)
{
  int tmp = 1;

  PluginSpeexContext * context = new PluginSpeexContext;
  context->bits = new SpeexBits;
  speex_bits_init(context->bits);

  if (codec->sampleRate == 16000)
    context->coderState = speex_decoder_init(&speex_wb_mode);
  else
    context->coderState = speex_decoder_init(&speex_nb_mode);

  speex_decoder_ctl(context->coderState, SPEEX_SET_ENH, &tmp);

  return context;
}

static int codec_decoder(const struct PluginCodec_Definition * codec, 
                                           void * _context,
                                     const void * from, 
                                       unsigned * fromLen,
                                           void * to,         
                                       unsigned * toLen,
                                   unsigned int * flag)
{
  struct PluginSpeexContext * context = (struct PluginSpeexContext *)_context;

  float floatData[WIDE_SAMPLES_PER_FRAME];
  short * sampleBuffer = (short *)to;

  // if this is a packet loss concealment frame, generate interpolated data
  // else decode the real data
  if (*flag & PluginCodec_CoderSilenceFrame)
    speex_decode(context->coderState, NULL, floatData);
  else {
    speex_bits_read_from(context->bits, (char *)from, *fromLen); 
    speex_decode(context->coderState, context->bits, floatData);     
  }

  // convert float to PCM
  int i;
  for (i = 0; i < codec->samplesPerFrame; i++) {
    float sample = floatData[i];
    if (sample < MinSampleValue)
      sample = MinSampleValue;
    else if (sample > MaxSampleValue)
      sample = MaxSampleValue;
    sampleBuffer[i] = (short)sample;
  }


  return 1;
}

static void destroy_decoder(const struct PluginCodec_Definition * codec, void * _context)
{
  struct PluginSpeexContext * context = (struct PluginSpeexContext *)_context;

  speex_bits_destroy(context->bits);
  free(context->bits);

  speex_decoder_destroy(context->coderState); 
  free(context);
}

/////////////////////////////////////////////////////////////////////////////

static struct PluginCodec_information licenseInfo = {
  //1081075346,                          // Sun 04 Apr 2004 10:42:26 AM UTC
  //1087351735,                          // Wed 16 Jun 2004 02:08:55 AM UTC
  1101695533,                            // Mon 29 Nov 2004 12:32:13 PM EST

  "Craig Southeren, Post Increment",                           // source code author
  "3.1",                                                       // source code version
  "craigs@postincrement.com",                                  // source code email
  "http://www.postincrement.com",                              // source code URL
  "Copyright (C) 2004 by Post Increment, All Rights Reserved", // source code copyright
  "MPL 1.0",                                                   // source code license
  PluginCodec_License_MPL,                                     // source code license

  "Speex",                                                     // codec description
  "Jean-Marc Valin, Xiph Foundation.",                         // codec author
  "1.0.3",                                                     // codec version
  "jean-marc.valin@hermes.usherb.ca",                          // codec email
  "http://www.speex.org",                                      // codec URL
  "(C) 2003 Xiph.Org Foundation, All Rights Reserved",         // codec copyright information
  "Xiph BSD license",                                          // codec license
  PluginCodec_License_BSD                                      // codec license code
};

static const char L16Desc[]  = { "L16" };

static const char sdpSpeex[]  = { "speex" };

#define	EQUIVALENCE_COUNTRY_CODE            9
#define	EQUIVALENCE_EXTENSION_CODE          0
#define	EQUIVALENCE_MANUFACTURER_CODE       61

#define	MICROSOFT_COUNTRY_CODE	            181
#define	MICROSOFT_T35EXTENSION	            0
#define	MICROSOFT_MANUFACTURER	            21324

#define XIPH_COUNTRY_CODE                   0xB5
#define XIPH_EXTENSION_CODE                 0x00
#define XIPH_MANUFACTURER_CODE              0x0026

static const unsigned char speexWNarrow8kHdr[] = 
{
  0x02, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0xa0, 0x00,  
  0x00, 0x00, 0xa0, 0x00, 
  0x04, 0x00, 0x10, 0x00,   

  0x00, 0x00, 0x00, 0x00, 

  // WAVEFORMATEX
  0x09, 0xa1,                //    WORD    wFormatTag;        format type 
  0x01, 0x00,                //    WORD    nChannels;         number of channels (i.e. mono, stereo...)  
  0x40, 0x1f, 0x00, 0x00,    //    DWORD   nSamplesPerSec;    sample rate   
  0xe8, 0x03, 0x00, 0x00,    //    DWORD   nAvgBytesPerSec;   for buffer estimation 

  0x14, 0x00,                //    WORD    nBlockAlign;       block size of data  
  0x10, 0x00,                //    WORD    wBitsPerSample;    Number of bits per sample of mono data 
  0x0e, 0x00,                //    WORD    cbSize;            The count in bytes of the size of extra information  

  // Speex additional information
  0x00, 0x01,                // SPEEXWAVEFORMAT_VERSION
  0x01, 0x00,                // nFramesPerBlock
  0x03, 0x00,                // nQuality
  0x00, 0x00,                // nMode
  0xf4, 0x01,                // nVbrQuality

  0x03, 0x00,                // nComplexity
  0x00, 0x00,                // nFlags

  // unknown
  0x00, 0x00
};

////////////////////////////////////////////////////////////////////////////////////////////////

#define CREATE_IETFSPEEX_CAP_DATA(desc, suffix, ordinal, rate) \
static const char ietfSpeex##suffix[] = "SpeexIETF" #desc; \
static const char ietfSpeex##suffix##Str[] = "speex sr=" #rate ";mode=" #ordinal ";vbr=off;cng=off"; \
static struct PluginCodec_H323NonStandardCodecData ietfSpeex##suffix##Cap = \
{ \
  NULL, \
  XIPH_COUNTRY_CODE, XIPH_EXTENSION_CODE, XIPH_MANUFACTURER_CODE, \
  (const unsigned char *)ietfSpeex##suffix##Str, sizeof(ietfSpeex##suffix##Str)-1, \
  NULL \
}; \

////////////////////////////////////////////////////////////////////////////////////////////////

#define CREATE_NARROW_SPEEX_CAP_DATA(desc, suffix, ordinal) \
static const char speex##suffix[] = "Speex" #desc; \
static const char speex##suffix##Str[] = "Speex bs4 Narrow" #ordinal; \
static struct PluginCodec_H323NonStandardCodecData speex##suffix##Cap = \
{ \
  NULL, \
  EQUIVALENCE_COUNTRY_CODE, EQUIVALENCE_EXTENSION_CODE, EQUIVALENCE_MANUFACTURER_CODE, \
  (const unsigned char *)speex##suffix##Str, sizeof(speex##suffix##Str)-1, \
  NULL \
}; \
CREATE_IETFSPEEX_CAP_DATA(desc, suffix, ordinal, 8000) \


#define DECLARE_NARROW_SPEEX_CODEC(prefix, suffix, ordinal, bitsPerFrame) \
/* Original OpenH323 capability */ \
{ \
  /* encoder */ \
  PLUGIN_CODEC_VERSION,               /* codec API version */ \
  &licenseInfo,                       /* license information */ \
  PluginCodec_MediaTypeAudio |        /* audio codec */ \
  PluginCodec_InputTypeRaw |          /* raw input data */ \
  PluginCodec_OutputTypeRaw |         /* raw output data */ \
  PluginCodec_RTPTypeShared |         /* share RTP code */ \
  PluginCodec_RTPTypeDynamic |        /* dynamic RTP type */ \
  PluginCodec_DecodeSilence,          /* can encode silence frames */ \
  prefix##suffix,                     /* text decription */ \
  L16Desc,                            /* source format */ \
  prefix##suffix,                     /* destination format */ \
  (void *)ordinal,                    /* user data */ \
  8000,                               /* samples per second */ \
  bitsPerFrame*50,                    /* raw bits per second */ \
  NARROW_NS_PER_FRAME,                /* nanoseconds per frame */ \
  NARROW_SAMPLES_PER_FRAME,           /* samples per frame */ \
  (bitsPerFrame + 7) / 8,             /* bytes per frame */ \
  1,                                  /* recommended number of frames per packet */ \
  1,                                  /* maximum number of frames per packet  */ \
  0,                                  /* IANA RTP payload code */ \
  sdpSpeex,                           /* RTP payload name */ \
  create_encoder,                     /* create codec function */ \
  destroy_encoder,                    /* destroy codec */ \
  codec_encoder,                      /* encode/decode */ \
  NULL,                               /* codec controls */ \
  PluginCodec_H323Codec_nonStandard,  /* h323CapabilityType */ \
  &prefix##suffix##Cap                /* h323CapabilityData */ \
}, \
{  \
  /* decoder */ \
  PLUGIN_CODEC_VERSION,               /* codec API version */ \
  &licenseInfo,                       /* license information */ \
  PluginCodec_MediaTypeAudio |        /* audio codec */ \
  PluginCodec_InputTypeRaw |          /* raw input data */ \
  PluginCodec_OutputTypeRaw |         /* raw output data */ \
  PluginCodec_RTPTypeShared |         /* share RTP code */ \
  PluginCodec_RTPTypeDynamic |        /* dynamic RTP type */ \
  PluginCodec_DecodeSilence,          /* can encode silence frames */ \
  prefix##suffix,                     /* text decription */ \
  prefix##suffix,                     /* source format */ \
  L16Desc,                            /* destination format */ \
  (void *)ordinal,                    /* user data */ \
  8000,                               /* samples per second */ \
  bitsPerFrame*50,                    /* raw bits per second */ \
  NARROW_NS_PER_FRAME,                /* nanoseconds per frame */ \
  NARROW_SAMPLES_PER_FRAME,           /* samples per frame */ \
  (bitsPerFrame+7)/8,                 /* bytes per frame */ \
  1,                                  /* recommended number of frames per packet */ \
  1,                                  /* maximum number of frames per packet */ \
  0,                                  /* IANA RTP payload code */ \
  sdpSpeex,                           /* RTP payload name */ \
  create_decoder,                     /* create codec function */ \
  destroy_decoder,                    /* destroy codec */ \
  codec_decoder,                      /* encode/decode */ \
  NULL,                               /* codec controls */ \
  PluginCodec_H323Codec_nonStandard,  /* h323CapabilityType */ \
  &prefix##suffix##Cap                /* h323CapabilityData */ \
} \

CREATE_NARROW_SPEEX_CAP_DATA(Narrow-5.95k, Narrow5k95,  2)
CREATE_NARROW_SPEEX_CAP_DATA(Narrow-8k,    Narrow8k,    3)
CREATE_NARROW_SPEEX_CAP_DATA(Narrow-11k,   Narrow11k,   4)
CREATE_NARROW_SPEEX_CAP_DATA(Narrow-15k,   Narrow15k,   5)
CREATE_NARROW_SPEEX_CAP_DATA(Narrow-18.2k, Narrow18k2,  6)
CREATE_NARROW_SPEEX_CAP_DATA(Narrow-24.6k, Narrow24k6,  7)

////////////////////////////////////////////////////////////////////////////////////////////////

#define CREATE_WIDE_SPEEX_CAP_DATA(desc, suffix, ordinal) \
static const char speex##suffix[] = "Speex" #desc; \
static const char speex##suffix##Str[] = "Speex bs4 Wide" #ordinal; \
static struct PluginCodec_H323NonStandardCodecData speex##suffix##Cap = \
{ \
  NULL, \
  EQUIVALENCE_COUNTRY_CODE, EQUIVALENCE_EXTENSION_CODE, EQUIVALENCE_MANUFACTURER_CODE, \
  (const unsigned char *)speex##suffix##Str, sizeof(speex##suffix##Str)-1, \
  NULL \
}; \
CREATE_IETFSPEEX_CAP_DATA(desc, suffix, ordinal, 16000)

#define DECLARE_WIDE_SPEEX_CODEC(prefix, suffix, ordinal, bitsPerFrame) \
/* Original OpenH323 capability */ \
{ \
  /* encoder */ \
  PLUGIN_CODEC_VERSION,               /* codec API version */ \
  &licenseInfo,                       /* license information */ \
  PluginCodec_MediaTypeAudio |        /* audio codec */ \
  PluginCodec_InputTypeRaw |          /* raw input data */ \
  PluginCodec_OutputTypeRaw |         /* raw output data */ \
  PluginCodec_RTPTypeShared |         /* share RTP code */ \
  PluginCodec_RTPTypeDynamic |        /* dynamic RTP type */ \
  PluginCodec_DecodeSilence,          /* can encode silence frames */ \
  prefix##suffix,                     /* text decription */ \
  L16Desc,                            /* source format */ \
  prefix##suffix,                     /* destination format */ \
  (void *)ordinal,                    /* user data */ \
  16000,                              /* samples per second */ \
  bitsPerFrame*50,                    /* raw bits per second */ \
  WIDE_NS_PER_FRAME,                  /* nanoseconds per frame */ \
  WIDE_SAMPLES_PER_FRAME,             /* samples per frame */ \
  (bitsPerFrame+7)/8,                 /* bytes per frame */ \
  1,                                  /* recommended number of frames per packet */ \
  1,                                  /* maximum number of frames per packet  */ \
  0,                                  /* IANA RTP payload code */ \
  sdpSpeex,                           /* RTP payload name */ \
  create_encoder,                     /* create codec function */ \
  destroy_encoder,                    /* destroy codec */ \
  codec_encoder,                      /* encode/decode */ \
  NULL,                               /* codec controls */ \
  PluginCodec_H323Codec_nonStandard,  /* h323CapabilityType */ \
  &prefix##suffix##Cap                /* h323CapabilityData */ \
}, \
{  \
  /* decoder */ \
  PLUGIN_CODEC_VERSION,               /* codec API version */ \
  &licenseInfo,                       /* license information */ \
  PluginCodec_MediaTypeAudio |        /* audio codec */ \
  PluginCodec_InputTypeRaw |          /* raw input data */ \
  PluginCodec_OutputTypeRaw |         /* raw output data */ \
  PluginCodec_RTPTypeShared |         /* share RTP code */ \
  PluginCodec_RTPTypeDynamic |        /* dynamic RTP type */ \
  PluginCodec_DecodeSilence,          /* can encode silence frames */ \
  prefix##suffix,                     /* text decription */ \
  prefix##suffix,                     /* source format */ \
  L16Desc,                            /* destination format */ \
  (void *)ordinal,                    /* user data */ \
  16000,                              /* samples per second */ \
  bitsPerFrame*50,                    /* raw bits per second */ \
  WIDE_NS_PER_FRAME,                  /* nanoseconds per frame */ \
  WIDE_SAMPLES_PER_FRAME,             /* samples per frame */ \
  (bitsPerFrame+7)/8,                 /* bytes per frame */ \
  1,                                  /* recommended number of frames per packet */ \
  1,                                  /* maximum number of frames per packet */ \
  0,                                  /* IANA RTP payload code */ \
  sdpSpeex,                           /* RTP payload name */ \
  create_decoder,                     /* create codec function */ \
  destroy_decoder,                    /* destroy codec */ \
  codec_decoder,                      /* encode/decode */ \
  NULL,                               /* codec controls */ \
  PluginCodec_H323Codec_nonStandard,  /* h323CapabilityType */ \
  &prefix##suffix##Cap                /* h323CapabilityData */ \
} \

CREATE_WIDE_SPEEX_CAP_DATA(Wide-11.55k, Wide11k5,  2)
CREATE_WIDE_SPEEX_CAP_DATA(Wide-17.6k,  Wide17k6,  3)
CREATE_WIDE_SPEEX_CAP_DATA(Wide-28.6k,  Wide28k6,  4)

////////////////////////////////////////////////////////////////////////////////////////////////

#define CREATE_NARROW_SPEEXW_CAP_DATA(desc, suffix, ordinal) \
static const char speexW##suffix[] = "SpeexW" #desc; \
static struct PluginCodec_H323NonStandardCodecData speexW##suffix##Cap = \
{ \
  NULL, \
  MICROSOFT_COUNTRY_CODE, MICROSOFT_T35EXTENSION, MICROSOFT_MANUFACTURER, \
  speexW##suffix##Hdr, sizeof(speexW##suffix##Hdr), \
  NULL \
}; \

#define DECLARE_NARROW_SPEEXW_CODEC(suffix, ordinal, bitsPerFrame) \
/* SpeexW OpenH323 capability */ \
{ \
  /* encoder */ \
  PLUGIN_CODEC_VERSION,               /* codec API version */ \
  &licenseInfo,                       /* license information */ \
  PluginCodec_MediaTypeAudio |        /* audio codec */ \
  PluginCodec_InputTypeRaw |          /* raw input data */ \
  PluginCodec_OutputTypeRaw |         /* raw output data */ \
  PluginCodec_RTPTypeShared |         /* share RTP code */ \
  PluginCodec_RTPTypeDynamic |        /* dynamic RTP type */ \
  PluginCodec_DecodeSilence,          /* can encode silence frames */ \
  speexW##suffix,                     /* text decription */ \
  L16Desc,                            /* source format */ \
  speexW##suffix,                     /* destination format */ \
  (void *)ordinal,                    /* user data */ \
  8000,                               /* samples per second */ \
  bitsPerFrame*50,                    /* raw bits per second */ \
  NARROW_NS_PER_FRAME,                /* nanoseconds per frame */ \
  NARROW_SAMPLES_PER_FRAME,           /* samples per frame */ \
  (bitsPerFrame+7)/8,                 /* bytes per frame */ \
  1,                                  /* recommended number of frames per packet */ \
  1,                                  /* maximum number of frames per packet  */ \
  0,                                  /* IANA RTP payload code */ \
  NULL,                               /* RTP payload name */ \
  create_encoder,                     /* create codec function */ \
  destroy_encoder,                    /* destroy codec */ \
  codec_encoder,                      /* encode/decode */ \
  NULL,                               /* codec controls */ \
  PluginCodec_H323Codec_nonStandard,  /* h323CapabilityType */ \
  &speexW##suffix##Cap                /* h323CapabilityData */ \
}, \
{  \
  /* decoder */ \
  PLUGIN_CODEC_VERSION,               /* codec API version */ \
  &licenseInfo,                       /* license information */ \
  PluginCodec_MediaTypeAudio |        /* audio codec */ \
  PluginCodec_InputTypeRaw |          /* raw input data */ \
  PluginCodec_OutputTypeRaw |         /* raw output data */ \
  PluginCodec_RTPTypeShared |         /* share RTP code */ \
  PluginCodec_RTPTypeDynamic,         /* dynamic RTP type */ \
  speexW##suffix,                     /* text decription */ \
  speexW##suffix,                     /* source format */ \
  L16Desc,                            /* destination format */ \
  (void *)ordinal,                    /* user data */ \
  8000,                               /* samples per second */ \
  bitsPerFrame*50,                    /* raw bits per second */ \
  NARROW_NS_PER_FRAME,                /* nanoseconds per frame */ \
  NARROW_SAMPLES_PER_FRAME,           /* samples per frame */ \
  (bitsPerFrame+7)/8,                 /* bytes per frame */ \
  1,                                  /* recommended number of frames per packet */ \
  1,                                  /* maximum number of frames per packet */ \
  0,                                  /* IANA RTP payload code */ \
  NULL,                               /* RTP payload name */ \
  create_decoder,                     /* create codec function */ \
  destroy_decoder,                    /* destroy codec */ \
  codec_decoder,                      /* encode/decode */ \
  NULL,                               /* codec controls */ \
  PluginCodec_H323Codec_nonStandard,  /* h323CapabilityType */ \
  &speexW##suffix##Cap                /* h323CapabilityData */ \
} \

CREATE_NARROW_SPEEXW_CAP_DATA(Narrow-8k,    Narrow8k,    3)

////////////////////////////////////////////////////////////////////////////////////////////////

#define NARROW_BITSPERFRAME_MODE2    119             // 5950
#define NARROW_BITSPERFRAME_MODE3    160             // 8000
#define NARROW_BITSPERFRAME_MODE4    220             // 11000 
#define NARROW_BITSPERFRAME_MODE5    300             // 15000
#define NARROW_BITSPERFRAME_MODE6    364             // 18200
#define NARROW_BITSPERFRAME_MODE7    492             // 26400

#define WIDE_BITSPERFRAME_MODE2    (NARROW_BITSPERFRAME_MODE2 + 112)     // 11550
#define WIDE_BITSPERFRAME_MODE3    (NARROW_BITSPERFRAME_MODE3 + 192)     // 17600
#define WIDE_BITSPERFRAME_MODE4    (NARROW_BITSPERFRAME_MODE4 + 352)     // 28600

static struct PluginCodec_Definition ver1SpeexCodecDefn[] = {
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow5k95,  2,   NARROW_BITSPERFRAME_MODE2),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow8k,    3,   NARROW_BITSPERFRAME_MODE3),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow11k,   4,   NARROW_BITSPERFRAME_MODE4),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow15k,   5,   NARROW_BITSPERFRAME_MODE5),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow18k2,  6,   NARROW_BITSPERFRAME_MODE6),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow24k6,  7,   NARROW_BITSPERFRAME_MODE7),

  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow5k95,  2,   NARROW_BITSPERFRAME_MODE2),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow8k,    3,   NARROW_BITSPERFRAME_MODE3),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow11k,   4,   NARROW_BITSPERFRAME_MODE4),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow15k,   5,   NARROW_BITSPERFRAME_MODE5),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow18k2,  6,   NARROW_BITSPERFRAME_MODE6),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow24k6,  7,   NARROW_BITSPERFRAME_MODE7),

  //DECLARE_SPEEXW_CODEC(Narrow5k95,  2),   // does not work
  DECLARE_NARROW_SPEEXW_CODEC(Narrow8k,   3,   NARROW_BITSPERFRAME_MODE3),
  //DECLARE_SPEEX_CODEC(Narrow11k,   4),    // does not work
  //DECLARE_SPEEX_CODEC(Narrow15k,   5),    // does not work
  //DECLARE_SPEEX_CODEC(Narrow18k2,  6),    // does not work
  //DECLARE_SPEEX_CODEC(Narrow24k6,  7)     // does not work
};

#define NUM_VER1_DEFNS   (sizeof(ver1SpeexCodecDefn) / sizeof(struct PluginCodec_Definition))

static struct PluginCodec_Definition ver2SpeexCodecDefn[] = {
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow5k95,  2,   NARROW_BITSPERFRAME_MODE2),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow8k,    3,   NARROW_BITSPERFRAME_MODE3),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow11k,   4,   NARROW_BITSPERFRAME_MODE4),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow15k,   5,   NARROW_BITSPERFRAME_MODE5),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow18k2,  6,   NARROW_BITSPERFRAME_MODE6),
  DECLARE_NARROW_SPEEX_CODEC(speex, Narrow24k6,  7,   NARROW_BITSPERFRAME_MODE7),

  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow5k95,  2,   NARROW_BITSPERFRAME_MODE2),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow8k,    3,   NARROW_BITSPERFRAME_MODE3),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow11k,   4,   NARROW_BITSPERFRAME_MODE4),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow15k,   5,   NARROW_BITSPERFRAME_MODE5),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow18k2,  6,   NARROW_BITSPERFRAME_MODE6),
  DECLARE_NARROW_SPEEX_CODEC(ietfSpeex, Narrow24k6,  7,   NARROW_BITSPERFRAME_MODE7),

  //DECLARE_SPEEXW_CODEC(Narrow5k95,  2),   // does not work
  DECLARE_NARROW_SPEEXW_CODEC(Narrow8k,    3,  NARROW_BITSPERFRAME_MODE3),
  //DECLARE_SPEEX_CODEC(Narrow11k,   4),    // does not work
  //DECLARE_SPEEX_CODEC(Narrow15k,   5),    // does not work
  //DECLARE_SPEEX_CODEC(Narrow18k2,  6),    // does not work
  //DECLARE_SPEEX_CODEC(Narrow24k6,  7)     // does not work

  DECLARE_WIDE_SPEEX_CODEC(speex, Wide11k5,   2,  WIDE_BITSPERFRAME_MODE2),
  DECLARE_WIDE_SPEEX_CODEC(speex, Wide17k6,   3,  WIDE_BITSPERFRAME_MODE3),
  DECLARE_WIDE_SPEEX_CODEC(speex, Wide28k6,   4,  WIDE_BITSPERFRAME_MODE4),

  DECLARE_WIDE_SPEEX_CODEC(ietfSpeex, Wide11k5,   2,  WIDE_BITSPERFRAME_MODE2),
  DECLARE_WIDE_SPEEX_CODEC(ietfSpeex, Wide17k6,   3,  WIDE_BITSPERFRAME_MODE3),
  DECLARE_WIDE_SPEEX_CODEC(ietfSpeex, Wide28k6,   4,  WIDE_BITSPERFRAME_MODE4),
};

#define NUM_VER2_DEFNS   (sizeof(ver2SpeexCodecDefn) / sizeof(struct PluginCodec_Definition))

/////////////////////////////////////////////////////////////////////////////

extern "C" {

PLUGIN_CODEC_DLL_API struct PluginCodec_Definition * PLUGIN_CODEC_GET_CODEC_FN(unsigned * count, unsigned version)
{
  if (version == 1) {
    *count = NUM_VER1_DEFNS;
    return ver1SpeexCodecDefn;
  }
  else
  {
    *count = NUM_VER2_DEFNS;
    return ver2SpeexCodecDefn;
  }
}

};

