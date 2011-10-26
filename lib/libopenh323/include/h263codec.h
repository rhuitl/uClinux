/*
 * h263codec.h
 *
 * H.323 protocol handler
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
 * Contributor(s): Guilhem Tardy (gtardy@marchnetworks.com)
 *
 * $Log: h263codec.h,v $
 * Revision 1.17  2005/11/30 13:05:01  csoutheren
 * Changed tags for Doxygen
 *
 * Revision 1.16  2004/04/22 22:35:00  csoutheren
 * Fixed mispelling of Guilhem Tardy - my apologies to him
 *
 * Revision 1.15  2004/04/22 14:22:20  csoutheren
 * Added RFC 2190 H.263 code as created by Guilhem Tardy and AliceStreet
 * Many thanks to them for their contributions.
 *
 * Revision 1.14  2003/08/04 00:03:22  dereksmithies
 * Reorganise tests for enabled
 *
 * Revision 1.13  2003/07/24 08:08:42  dereksmithies
 * Update to use vich263 codec, instead of ffmpeg.
 *
 * Revision 1.12  2003/06/06 05:18:54  dereksmithies
 * Fix startup delay bug. Remove all large packets from the network. Improve reliability.
 *
 * Revision 1.11  2003/05/27 09:22:55  dereksmithies
 * Updates for code revisions in h263 codec
 *
 * Revision 1.10  2003/05/14 13:47:58  rjongbloed
 * Removed static "initialisation" function as this should be done
 *   internally and not in the application.
 *
 * Revision 1.9  2003/05/05 11:59:21  robertj
 * Changed to use autoconf style selection of options and subsystems.
 *
 * Revision 1.8  2003/05/02 04:22:10  craigs
 * Added lots of extra H.263 support
 *
 * Revision 1.7  2003/04/27 09:16:38  rogerh
 * use PBYTE_ORDER instead of endian.h
 *
 * Revision 1.6  2003/04/21 21:50:22  dereks
 * Implement suggestion from Guilhem Tardy. Many thanks.
 *
 * Revision 1.5  2003/04/16 04:26:57  dereks
 * Initial release of h263 codec, which utilises the ffmpeg library.
 * Thanks to Guilhem Tardy, and to AliceStreet.
 *
 * Revision 1.4  2002/09/16 01:14:15  robertj
 * Added #define so can select if #pragma interface/implementation is used on
 *   platform basis (eg MacOS) rather than compiler, thanks Robert Monaghan.
 *
 * Revision 1.3  2002/09/03 06:19:36  robertj
 * Normalised the multi-include header prevention ifdef/define symbol.
 *
 * Revision 1.2  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.1  2002/05/19 22:32:46  dereks
 * Initial release of stub file for h263 codec. Thanks Guilhem Tardy.
 *
 *
 *
 */
 
/*
 * Initial release notes from Guilhem Tardy::
 *
 * Added support for video capabilities & codec, only tested under Linux!
 * The code for varying bit rate is copied from h261codec.cxx,
 * until it is moved to a separate file common to both video codecs.
 *
 */

#ifndef __OPAL_H263CODEC_H
#define __OPAL_H263CODEC_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#include <openh323buildopts.h>


#include "h323caps.h"

#if defined(H323_VICH263) || defined(H323_RFC2190_AVCODEC)

class H263Decoder;
class H263Encoder;

///////////////////////////////////////////////////////////////////////////////

/**This class is a H.263 video capability.
 */

class H323_H263Capability : public H323VideoCapability
{
  PCLASSINFO(H323_H263Capability, H323VideoCapability)

  public:
  /**@name Construction */
  //@{
    /**Create a new H263 Capability
     */
    H323_H263Capability(
      unsigned sqcifMPI,
      unsigned qcifMPI,
      unsigned cifMPI,
      unsigned cif4MPI,
      unsigned cif16MPI,
      unsigned maxBitRate = 850,
      unsigned videoFrameRate = 25,
      BOOL unrestrictedVector = FALSE,
      BOOL arithmeticCoding = FALSE,
      BOOL advancedPrediction = FALSE,
      BOOL pbFrames = FALSE,
      BOOL temporalSpatialTradeOff = TRUE,
      unsigned hrd_B = 0,
      unsigned bppMaxKb = 0,
      unsigned slowSqcifMPI = 0,
      unsigned slowQcifMPI = 0,
      unsigned slowCifMPI = 0,
      unsigned slowCif4MPI = 0,
      unsigned slowCif16MPI = 0,
      BOOL errorCompensation = FALSE
    );
  //@}

  /**@name Overrides from class PObject */
  //@{
    /**Create a copy of the object.
      */
    virtual PObject * Clone() const;
  //@}

  
  /**@name Overrides from class PObject */
  //@{
    /**Compare object
      */
    Comparison Compare(const PObject & obj) const;
   //@}

  /**@name Identification functions */
  //@{
    /**Get the sub-type of the capability. This is a code dependent on the
       main type of the capability.

       This returns one of the four possible combinations of mode and speed
       using the enum values of the protocol ASN H245_AudioCapability class.
     */
    virtual unsigned GetSubType() const;

    /**Get the name of the media data format this class represents.
     */
    virtual PString GetFormatName() const;
  //@}

  /**@name Protocol manipulation */
  //@{
    /**This function is called whenever and outgoing TerminalCapabilitySet
       or OpenLogicalChannel PDU is being constructed for the control channel.
       It allows the capability to set the PDU fields from information in
       members specific to the class.

       The default behaviour sets the data rate field in the PDU.
     */
    virtual BOOL OnSendingPDU(
      H245_VideoCapability & pdu  ///< PDU to set information on
    ) const;

    /**This function is called whenever and outgoing RequestMode
       PDU is being constructed for the control channel. It allows the
       capability to set the PDU fields from information in members specific
       to the class.

       The default behaviour sets the resolution and bit rate.
     */
    virtual BOOL OnSendingPDU(
      H245_VideoMode & pdu  ///< PDU to set information on
    ) const;

    /**This function is called whenever and incoming TerminalCapabilitySet
       or OpenLogicalChannel PDU has been used to construct the control
       channel. It allows the capability to set from the PDU fields,
       information in members specific to the class.

       The default behaviour gets the data rate field from the PDU.
     */
    virtual BOOL OnReceivedPDU(
      const H245_VideoCapability & pdu  ///< PDU to set information on
    );

    /**Create the codec instance, allocating resources as required.
     */
    virtual H323Codec * CreateCodec(
      H323Codec::Direction direction  ///< Direction in which this instance runs
    ) const;

#if 0
    /** Get sqcifMPI
     */
    unsigned GetSQCIFMPI() const
      { return sqcifMPI); }

    /** Get qcifMPI
     */
    unsigned GetQCIFMPI() const
      { return qcifMPI; }

    /** Get cifMPI
     */
    unsigned GetCIFMPI() const
      { return cifMPI; }

    /** Get cif4MPI
     */
    unsigned GetCIF4MPI() const
      { return cif4MPI; }

    /** Get cif16MPI
     */
    unsigned GetCIF16MPI() const
      { return cif16MPI; }

    /** Get maximum bit rate
     */
    unsigned GetMaxBitRate() const
      { return maxBitRate; }

    /** Get unrestrictedVector capabilty
     */
    BOOL GetUnrestrictedVectorCapability() const
      { return unrestrictedVector; }

    /** Get arithmeticCoding capabilty
     */
    BOOL GetArithmeticCodingCapability() const
      { return arithmeticCoding; }

    /** Get advancedPrediction capabilty
     */
    BOOL GetAdvancedPredictionCapability() const
      { return advancedPrediction; }

    /** Get  pbFrames capabilty
     */
    BOOL GetPbFramesCapability() const
      { return pbFrames; }

    /** Get temporal/spatial tradeoff capabilty
     */
    BOOL GetTemporalSpatialTradeOffCapability() const
      { return temporalSpatialTradeOff; }

    /** Get hrd_B
     */
    BOOL GetHrd_B() const
      { return hrd_B; }

    /** Get bppMaxKb
     */
    BOOL GetBppMaxKb() const
      { return bppMaxKb; }

    /** Get slowSqcifMPI
     */
    unsigned GetSlowSQCIFMPI() const
      { return (sqcifMPI<0?-sqcifMPI:0); }

    /** Get slowQcifMPI
     */
    unsigned GetSlowQCIFMPI() const
      { return (qcifMPI<0?-qcifMPI:0); }

    /** Get slowCifMPI
     */
    unsigned GetSlowCIFMPI() const
      { return (cifMPI<0?-cifMPI:0); }

    /** Get slowCif4MPI
     */
    unsigned GetSlowCIF4MPI() const
      { return (cif4MPI<0?-cif4MPI:0); }

    /** Get slowCif16MPI
     */
    unsigned GetSlowCIF16MPI() const
      { return (cif16MPI<0?-cif16MPI:0); }

    /** Get errorCompensation capabilty
     */
    BOOL GetErrorCompensationCapability() const
      { return errorCompensation; }
#endif

  //@}

protected:
    // H.263 v1
    signed sqcifMPI;		// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}
    signed qcifMPI;		// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}
    signed cifMPI;		// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}
    signed cif4MPI;		// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}
    signed cif16MPI;		// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}

    unsigned maxBitRate;	// units of bit/s
    unsigned videoFrameRate;   // frames per second.

    BOOL     unrestrictedVector;
    BOOL     arithmeticCoding;
    BOOL     advancedPrediction;
    BOOL     pbFrames;
    BOOL     temporalSpatialTradeOff;

    long unsigned hrd_B;	// units of 128 bits
    unsigned bppMaxKb;		// units of 1024 bits

    BOOL     errorCompensation;
};

///////////////////////////////////////////////////////////////
/**This class is a H.263 video codec.
 */
class H323_H263Codec : public H323VideoCodec
{
  PCLASSINFO(H323_H263Codec, H323VideoCodec)

  public:
    /**Create a new H263 video codec
     */
    H323_H263Codec(
      Direction direction,	///< Direction in which this instance runs      
      unsigned sqcifMPI,
      unsigned qcifMPI,
      unsigned cifMPI,
      unsigned cif4MPI,
      unsigned cif16MPI,
      unsigned maxBitRate,
      unsigned videoFrameRate
    );

    ~H323_H263Codec();

    /**Encode the data from the appropriate device.
       This will encode a frame of data for transmission. The exact size and
       description of the data placed in the buffer is codec dependent but
       should be less than H323Capability::GetTxFramesInPacket() *
       OpalMediaFormat::GetFrameSize()  in length.

       The length parameter is filled with the actual length of the encoded
       data, often this will be the same as the size parameter.

       This function is called every GetFrameRate() timestamp units, so MUST
       take less than (or equal to) that amount of time to complete!

       Note that a returned length of zero indicates that time has passed but
       there is no data encoded. This is typically used for silence detection
       in an audio codec.
     */
    virtual BOOL Read(
      BYTE * buffer,		///< Buffer of encoded data
      unsigned & length,	///< Actual length of encoded data buffer
      RTP_DataFrame & rtpFrame	///< RTP data frame
    );

    /**Decode the data and output it to appropriate device.
       This will decode a single frame of received data. The exact size and
       description of the data required in the buffer is codec dependent but
       should be less than H323Capability::GetRxFramesInPacket() *
       OpalMediaFormat::GetFrameSize()  in length.

       It is expected this function anunciates the data. That is, for example
       with audio data, the sound is output on a speaker.

       This function is called every GetFrameRate() timestamp units, so MUST
       take less than that amount of time to complete!
     */
    virtual BOOL Write(
      const BYTE * buffer,	  ///< Buffer of encoded data
      unsigned length,		  ///< Length of encoded data buffer
      const RTP_DataFrame & rtp,  ///< RTP data frame
      unsigned & written	  ///< Number of bytes used from data buffer
    );

    /**Get the frame rate in RTP timestamp units.
      */
    virtual unsigned GetFrameRate() const { return timestampDelta; }

    /**Set the quality level of transmitted video data. 
       Is irrelevant when this codec is used to receive video data.
       Has a value of 1 (good quality) to 31 (poor quality).
       Quality is improved at the expense of bit rate.
    */
    void SetTxQualityLevel(int qLevel);
 
    /**Set the number of blocks in the background that need
       to be transmitted with each frame
    */
    void SetBackgroundFill(int fillLevel);

    /**Process a request for a new frame, 
       as part of the picture has been lost.
    */
    virtual void OnLostPartialPicture();

    /**
       Process a request for a new frame, 
       as all of the picture has been lost.
    */
    virtual void OnLostPicture();

    /**
       The ffmpeg library calls this routine, everytime it has a new packet to 
       send. Note that for every encode thread, this 1 method is called. Consequently, 
       code is required to separate out packets from different encode threads.
    */
    static void RtpCallback(void *data, int size, int packetNumber);

  protected:
    BOOL Resize(int width, int height);

    BOOL RenderFrame(); 
    BOOL RenderFrame(const void * buffer);



    void InitialiseCodec();
    void CloseCodec();


    unsigned timestampDelta;

    H263Decoder *videoDecoder;
    H263Encoder *videoEncoder;

    int now;
    BYTE * rvts;
    int ndblk, nblk;
   
    PTime           startTime;
    PINDEX          bitsSent;

    unsigned        lastebits;
};

#endif // H323_VICH263
#endif // __OPAL_H263CODEC_H




/////////////////////////////////////////////////////////////////////////////
