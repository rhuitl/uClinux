/*
 * AMR Plugin codec for OpenH323/OPAL
 *
 * Copyright (C) 2004 MX Telecom Ltd.
 *
 * $Id: amrcodec.c,v 1.3 2005/06/08 15:36:00 shorne Exp $
 */


/*Disable some warnings on VC++*/
#ifdef _MSC_VER
#pragma warning(disable : 4018)
#pragma warning(disable : 4100)
#endif

#include "opalplugin.h"
#include "src/interf_enc.h"
#include "src/interf_dec.h"

PLUGIN_CODEC_IMPLEMENT("AMR")
#include <stdio.h>
#include <malloc.h>

/***************************************************************************
 *
 * This plugin implements an interface to the AMR-NB codec for OpenH323.
 *
 * The amr codec itself is not distributed with this plugin. See amrcodec.txt
 * in the src subdirectory of the plugin source.
 *
 **************************************************************************/
    
/* generic parameters; see H.245 Annex I */
enum
{
    GENERIC_PARAMETER_AMR_MAXAL_SDUFRAMES = 0,
    GENERIC_PARAMETER_AMR_BITRATE,
    GENERIC_PARAMETER_AMR_GSMAMRCOMFORTNOISE,
    GENERIC_PARAMETER_AMR_GSMEFRCOMFORTNOISE,
    GENERIC_PARAMETER_AMR_IS_641COMFORTNOISE,
    GENERIC_PARAMETER_AMR_PDCEFRCOMFORTNOISE
};

/* values of the bit rate parameter */
enum
{
    AMR_BITRATE_475 = 0,
    AMR_BITRATE_515,
    AMR_BITRATE_590,
    AMR_BITRATE_670,
    AMR_BITRATE_740,
    AMR_BITRATE_795,
    AMR_BITRATE_1020,
    AMR_BITRATE_1220
};
    

/* expected number of bytes, for a given mode */
static short bytes_per_frame[16]={ 13, 14, 16, 18, 19, 21, 26, 31, 6, 0, 0, 0, 0, 0, 0, 0 };

#define AMR_Mode  7

// this is what we hand back when we are asked to create an encoder
typedef struct
{
    void *encoder_state;  // Encoder interface's opaque state
    int mode;             // current mode
} AmrEncoderContext;

/////////////////////////////////////////////////////////////////////////////

static void * amr_create_encoder(const struct PluginCodec_Definition * codec)
{
    AmrEncoderContext *ctx = malloc(sizeof(AmrEncoderContext));
    if(ctx == NULL ) {
        fprintf(stderr,"AMR codec: unable to allocate context");
        return NULL;
    }

    ctx->encoder_state = Encoder_Interface_init(0);
    if(ctx->encoder_state == NULL ) {
        // Encoder_Interface_init writes an error msg in this case; no need to
        // repeat
        free(ctx);
        return NULL;
    }

    ctx->mode = (int)codec->userData; // start off in mode 7
    return ctx;
}

static void * amr_create_decoder(const struct PluginCodec_Definition * codec)
{
    return Decoder_Interface_init();
}

static void amr_destroy_encoder(const struct PluginCodec_Definition * codec, void * context)
{
    AmrEncoderContext *ctx = (AmrEncoderContext *)context;
    Encoder_Interface_exit(ctx->encoder_state);
    free(ctx);
}

static void amr_destroy_decoder(const struct PluginCodec_Definition * codec, void * context)
{
    Decoder_Interface_exit(context);
}

static int amr_codec_encoder(const struct PluginCodec_Definition * codec, 
                                           void * context,
                                     const void * from, 
                                       unsigned * fromLen,
                                           void * to,         
                                       unsigned * toLen,
                                   unsigned int * flag)
{
    AmrEncoderContext *ctx = (AmrEncoderContext *)context;
    unsigned int mode = ctx->mode;

    if( *fromLen != 160*sizeof(short)) {
	fprintf(stderr,"AMR codec: audio frame of size %u doesn't match expected %u\n",
		*fromLen,160*sizeof(short));
	return 0;
    }

    if(*toLen < bytes_per_frame[mode]) {
	fprintf(stderr,"AMR codec: output buffer of size %u too short for mode %u\n", *toLen, mode );
	return 0;
    }

  /*   fprintf(stderr,"AMR codec: encoding to mode %u size %u\n", mode, *toLen); */

    *toLen = Encoder_Interface_Encode(ctx->encoder_state,mode,(void *)from,to,0);
    return 1; 
}

#if 0
static void hexprint(const void *ptr, unsigned len)
{
    int i;
    const char *p = (const char *)ptr;
    
    for(i=0; i<len; i++) {
        fprintf(stderr,"%02x",p[i]);
    }
}
#endif

static int amr_codec_decoder(const struct PluginCodec_Definition * codec, 
                                           void * context,
                                     const void * from, 
                                       unsigned * fromLen,
                                           void * to,         
                                       unsigned * toLen,
                                   unsigned int * flag)
{
//  unsigned int mode;
    
    if( *fromLen < 1 )
	return 0;

/*   // get the AMR mode from the first nibble of the frame
    mode = *(char *)from & 0xF;

    // check that the input is long enough for the decoder
    if( *fromLen != bytes_per_frame[mode] ) {
	fprintf(stderr,"AMR codec: packet size %u doesn't match expected %u for mode %u\n", *fromLen,bytes_per_frame[mode], mode );
	return 0;
    }
*/  
    Decoder_Interface_Decode( context, (void *)from, (short *)to, 0 );
#if 0
    fprintf(stderr,"Decoded AMR frame [");
    hexprint(from,*fromLen);
    fprintf(stderr,"]\nResult: [");
    hexprint(to,40);
    fprintf(stderr,"...]\n");
#endif

    // return the number of decoded bytes to the caller
    *toLen = 160*sizeof(short);

    return 1;
}

static int amr_set_quality(const struct PluginCodec_Definition * codec, void * context, 
                           const char * name, void * parm, unsigned * parmLen)
{
    AmrEncoderContext *ctx = (AmrEncoderContext *)context;
    int q;

    if(*parmLen != sizeof(q))
        return -1;
    q = *(int *)parm;

    if( q < 1 || q > 31)
        return -1;
    /* 1-3   -> mode 7
       4-7   -> mode 6
       ...
       28-31 -> mode 0
    */
    ctx->mode = 7-(q/4);
    return 0;
}

static int amr_get_quality(const struct PluginCodec_Definition * codec, void * context, 
                           const char * name, void * parm, unsigned * parmLen)
{
    AmrEncoderContext *ctx = (AmrEncoderContext *)context;

    if(*parmLen != sizeof(int))
        return -1;

    *(int *)parm = (7-ctx->mode)*4;
    return 0;
}


/////////////////////////////////////////////////////////////////////////////


static struct PluginCodec_information licenseInfo = {
    // Tue 13 Jul 2004 00:11:32 UTC =
    1089677492,

    "Richard van der Hoff, MX Telecom Ltd.",                     // source code author
    "$Ver$",                                                     // source code version
    "richardv@mxtelecom.com",                                    // source code email
    "http://www.mxtelecom.com",                                  // source code URL
    "Copyright (C) 2004 MX Telecom Ltd.", 		         // source code copyright
    "None",                                                      // source code license  // FIXME
    PluginCodec_License_None,                                    // source code license
    
    "GSM-AMR (Adaptive Multirate Codec)",                        // codec description
    "3rd Generation Partnership Project",                        // codec author
    NULL,                                                        // codec version
    NULL,	                                                 // codec email
    "http://www.3gpp.org",	                                 // codec URL
    "",          						 // codec copyright information
    "", 							 // codec license
    PluginCodec_License_RoyaltiesRequired                        // codec license code
};


static const struct PluginCodec_H323GenericParameterDefinition amr_params[] =
{
    {1,
     GENERIC_PARAMETER_AMR_MAXAL_SDUFRAMES,
     PluginCodec_GenericParameter_ShortMin,
     {1}}
};
     
static const struct PluginCodec_H323GenericCodecData amrcap =
{
    "0.0.8.245.1.1.1",						// capability identifier (Ref: Table I.1 in H.245)
    122,
    1,
    amr_params
};

static struct PluginCodec_ControlDefn amrEncoderControlDefn[] = {
    {"set_quality", amr_set_quality},
    {"get_quality", amr_get_quality},
    {NULL, NULL}
};



static const struct PluginCodec_Definition amrCodecDefn[] = {
    { 
	// encoder
	PLUGIN_CODEC_VERSION,               	// codec API version
	&licenseInfo,                       	// license information

	PluginCodec_MediaTypeAudio |        	// audio codec
	PluginCodec_InputTypeRaw |          	// raw input data
	PluginCodec_OutputTypeRaw |         	// raw output data
	PluginCodec_RTPTypeDynamic,         	// dynamic RTP type
	
	"GSM-AMR",	                        // text decription
	"L16",                              	// source format
	"GSM-AMR",                             	// destination format
	
	(void *)AMR_Mode,                       // user data

	8000,                               	// samples per second
	0,		                        // raw bits per second
	20000,                              	// nanoseconds per frame
	160,                      		// samples per frame
	32,                  			// bytes per frame; 32 because
						// the sample coder stomps on
						// an extra byte
	
	1,                                  	// recommended number of frames per packet
	1,                                  	// maximum number of frames per packet
	0,                                  	// IANA RTP payload code
	"AMR",                                  // RTP payload name
	
	amr_create_encoder,                    	// create codec function
	amr_destroy_encoder,                   	// destroy codec
	amr_codec_encoder,                     	// encode/decode
	amrEncoderControlDefn,                 	// codec controls
        
	PluginCodec_H323Codec_generic,  	// h323CapabilityType
	(struct PluginCodec_H323GenericCodecData *)&amrcap
						// h323CapabilityData
    },

    { 
	// decoder
	PLUGIN_CODEC_VERSION,               	// codec API version
	&licenseInfo,                       	// license information

	PluginCodec_MediaTypeAudio |        	// audio codec
	PluginCodec_InputTypeRaw |          	// raw input data
	PluginCodec_OutputTypeRaw |         	// raw output data
	PluginCodec_RTPTypeDynamic,         	// dynamic RTP type

	"GSM-AMR",                           	// text decription
	"GSM-AMR",                           	// source format
	"L16",                            	// destination format

	(void *)AMR_Mode,                       // user data

	8000,                               	// samples per second
	0,		                        // raw bits per second
	30000,                              	// nanoseconds per frame
	160,                      		// samples per frame
	31,                  			// bytes per frame
	1,                                  	// recommended number of frames per packet
	1,                                  	// maximum number of frames per packet
	0,                                  	// IANA RTP payload code
	"AMR",                                  // RTP payload name

	amr_create_decoder,                    	// create codec function
	amr_destroy_decoder,                   	// destroy codec
	amr_codec_decoder,                     	// encode/decode
	NULL,                                	// codec controls
	
	PluginCodec_H323Codec_generic,  	// h323CapabilityType 
	(struct PluginCodec_H323GenericCodecData *)&amrcap
						// h323CapabilityData
    }
};

#define NUM_DEFNS   (sizeof(amrCodecDefn) / sizeof(struct PluginCodec_Definition))

/////////////////////////////////////////////////////////////////////////////

PLUGIN_CODEC_DLL_API const struct PluginCodec_Definition * PLUGIN_CODEC_GET_CODEC_FN(unsigned * count, unsigned version)
{
  *count = NUM_DEFNS;
  return amrCodecDefn;
}


#ifdef _MSC_VER
#pragma warning(default : 4018)
#pragma warning(default : 4100)
#endif