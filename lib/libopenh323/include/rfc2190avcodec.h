/*
 * rfc2190avcodec.h
 *
 * H.323 protocol handler
 *
 * Open H323 Library
 *
 * Copyright (c) 2001 March Networks Corporation
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
 * Contributor(s): Guilhem Tardy (gtardy@salyens.com)
 *
 * $Log: rfc2190avcodec.h,v $
 * Revision 1.4  2004/05/12 23:18:44  csoutheren
 * Adjusted copyright notices for ffh263 and rfc2190 files
 *
 * Revision 1.3  2004/04/24 00:41:14  rjongbloed
 * Fixed file names in header comment.
 *
 * Revision 1.2  2004/04/22 22:35:00  csoutheren
 * Fixed mispelling of Guilhem Tardy - my apologies to him
 *
 * Revision 1.1  2004/04/22 22:20:34  csoutheren
 * New files for RFC2190 H.263 video codec
 * Added RFC 2190 H.263 code as created by Guilhem Tardy and AliceStreet
 * Many thanks to them for their contributions.
 *
 * Revision 1.5  2003/10/31 00:00:00  Guilhem Tardy
 * Restored RFC2190 compliance.
 *
 * Revision 1.4  2003/10/05 00:00:00  Guilhem Tardy
 * Reintroduce ffmpeg own packet slicing technique (now working better).
 *
 * Revision 1.3  2003/08/04 00:03:16  dereksmithies
 * Reorganise tests for enabled
 *
 * Revision 1.2  2003/07/31 05:08:24  dereksmithies
 * Switch to manual packet fragment technique. Much more reliable, especially so on windows.
 *
 * Revision 1.1  2003/07/24 05:23:06  dereksmithies
 * Move ffmpeg h263 support to this file, and designate non standard.
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

#ifndef __OPAL_FFH263CODEC_H
#define __OPAL_FFH263CODEC_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#ifdef H323_RFC2190_AVCODEC
struct AVCodec;
struct AVCodecContext;
struct AVFrame;
 
///////////////////////////////////////////////////////////////////////////////

/**This class is a H.263 video capability.
 */
class H323_RFC2190_H263Capability : public H323VideoCapability
{
  PCLASSINFO(H323_RFC2190_H263Capability, H323VideoCapability)

  public:
  /**@name Construction */
  //@{
    /**Create a new FFH263 Capability
     */ 
    H323_RFC2190_H263Capability(
      unsigned sqcifMPI = 1,	// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}
      unsigned qcifMPI = 2,
      unsigned cifMPI = 4,
      unsigned cif4MPI = 8,
      unsigned cif16MPI = 32,
      unsigned maxBitRate = 400,
      BOOL unrestrictedVector = FALSE,
      BOOL arithmeticCoding = FALSE, // not supported
      BOOL advancedPrediction = FALSE,
      BOOL pbFrames = FALSE,
      BOOL temporalSpatialTradeOff = FALSE, // not supported
      unsigned hrd_B = 0, // not supported
      unsigned bppMaxKb = 0, // not supported
      unsigned slowSqcifMPI = 0,
      unsigned slowQcifMPI = 0,
      unsigned slowCifMPI = 0,
      unsigned slowCif4MPI = 0,
      unsigned slowCif16MPI = 0,
      BOOL errorCompensation = FALSE // not supported
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
      H245_VideoCapability & pdu  /// PDU to set information on
    ) const;

    /**This function is called whenever and outgoing RequestMode
       PDU is being constructed for the control channel. It allows the
       capability to set the PDU fields from information in members specific
       to the class.

       The default behaviour sets the resolution and bit rate.
     */
    virtual BOOL OnSendingPDU(
      H245_VideoMode & pdu  /// PDU to set information on
    ) const;

    /**This function is called whenever and incoming TerminalCapabilitySet
       or OpenLogicalChannel PDU has been used to construct the control
       channel. It allows the capability to set from the PDU fields,
       information in members specific to the class.

       The default behaviour gets the data rate field from the PDU.
     */
    virtual BOOL OnReceivedPDU(
      const H245_VideoCapability & pdu  /// PDU to set information on
    );

    /**Create the codec instance, allocating resources as required.
     */
    virtual H323Codec * CreateCodec(
      H323Codec::Direction direction  /// Direction in which this instance runs
    ) const;

    /** Get sqcifMPI
     */
    unsigned GetSQCIFMPI() const
      { return sqcifMPI; }

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
  //@}

protected:

    signed sqcifMPI;		// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}
    signed qcifMPI;
    signed cifMPI;
    signed cif4MPI;
    signed cif16MPI;

    unsigned maxBitRate;	// units of bit/s

    BOOL     unrestrictedVector;
    BOOL     arithmeticCoding;
    BOOL     advancedPrediction;
    BOOL     pbFrames;
    BOOL     temporalSpatialTradeOff;

    long unsigned hrd_B;	// units of 128 bits
    unsigned bppMaxKb;		// units of 1024 bits

    BOOL     errorCompensation;
};

////////////////////////////////////////////////////////////////

class H263Packet : public PObject
{
  PCLASSINFO(H263Packet, PObject)

  public:

    H263Packet() { data_size = hdr_size = 0; hdr = data = NULL; };
    ~H263Packet() {};

    void Store(void *data, int data_size, void *hdr, int hdr_size);
    BOOL Read(unsigned & length, RTP_DataFrame & frame);

  private:

    void *data;
    int data_size;
    void *hdr;
    int hdr_size;
};

PDECLARE_LIST(H263PacketList, H263Packet)
#if 0
{
#endif
};

//////////////////////////////////////////////////////////////////////

/**This class is a H.263 video codec.
 */
class H323_RFC2190_H263Codec : public H323VideoCodec
{
  PCLASSINFO(H323_RFC2190_H263Codec, H323VideoCodec)

  public:
    /**Create a new H263 video codec
     */
    H323_RFC2190_H263Codec(
      Direction direction,	/// Direction in which this instance runs
      signed sqcifMPI,		/// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}
      signed qcifMPI,
      signed cifMPI,
      signed cif4MPI,
      signed cif16MPI,
      unsigned maxBitRate,
      BOOL unrestrictedVector,
      BOOL arithmeticCoding,
      BOOL advancedPrediction,
      BOOL pbFrames
    );

    ~H323_RFC2190_H263Codec();

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
      BYTE * buffer,		/// Buffer of encoded data
      unsigned & length,	/// Actual length of encoded data buffer
      RTP_DataFrame & rtpFrame	/// RTP data frame
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
      const BYTE * buffer,	  /// Buffer of encoded data
      unsigned length,		  /// Length of encoded data buffer
      const RTP_DataFrame & rtp,  /// RTP data frame
      unsigned & written	  /// Number of bytes used from data buffer
    );

    /**Get the frame rate in RTP timestamp units.
      */
    virtual unsigned GetFrameRate() const { return rtpTimestampDelta; }

    /**Quality of the transmitted video. 1 is good, 31 is poor.
     */
    void SetTxQualityLevel(int qLevel);
 
    /**Minimum quality limit for the transmitted video.
     * Default is 1. Encode quality will not be set below this value.
     */
    virtual void SetTxMinQuality(int qlevel);

    /**Maximum quality limit for the transmitted video.
     * Default is 24. Encode quality will not be set above this value.
     */
    virtual void SetTxMaxQuality(int qlevel);

    /**Number of blocks (that haven't changed) transmitted with each 
     * frame. These blocks fill in the background.
     */
    void SetBackgroundFill(int fillLevel);

    /**Set the current value for video control mode
     * return the resulting value video control mode
     */
    virtual void SetVideoMode(unsigned mode);
    
    /**Set maximum bitrate when transmitting video.  A value of 0 disables bit rate
       control.  The average bitrate will be less depending on channel dead time,
       i.e. time that the channel could be transmitting bits but is not.
     */
    virtual BOOL SetMaxBitRate(unsigned bitRate);

    /**Process a OnVideoTemporalSpatialTradeOff indication from remote endpoint.
       The default behaviour does nothing.
     */
    virtual void OnVideoTemporalSpatialTradeOff();

    /**Process a request for a new frame, 
       as part of the picture has been lost.
    */
    virtual void OnLostPartialPicture();

    /**Process a request for a new frame, 
       as the entire picture has been lost.
    */
    virtual void OnLostPicture();

    /**
       The ffmpeg library calls this routine, everytime it has a new packet to
       send. Note that for every encode thread, this one method is called. Consequently,
       the 'priv_data' is used to separate out packets from different encode threads.
    */
    static void RtpCallback(void *data, int data_size,
                            void *hdr, int hdr_size, void *priv_data);

  protected:

    BOOL Resize(int width, int height);

    BOOL RenderFrame(const void *buffer);
    BOOL RenderFrame(const AVFrame *pict);

    BOOL OpenCodec();

    void CloseCodec();

    H263PacketList encodedPackets;
    H263PacketList unusedPackets;

    PBYTEArray encFrameBuffer;
    PBYTEArray rawFrameBuffer;

    PINDEX encFrameLen;
    PINDEX rawFrameLen;

    AVCodec        *codec;
    AVCodecContext *context;
    AVFrame        *picture;

    PTime lastFrameTime;
    unsigned rtpTimestampDelta;
    PTime lastPacketTime;
    PINDEX lastPacketBits;

    enum StdSize {UnknownStdSize, SQCIF = 1, QCIF, CIF, CIF4, CIF16, NumStdSizes};

    static int GetStdSize(int width, int height); //
    static int GetStdWidth (StdSize size);
    static int GetStdHeight (StdSize size);

    signed videoFrameRate[NumStdSizes];	/// {1..3600 units seconds/frame, 1..32 units 1/29.97 Hz}
    StdSize videoSize;
    BOOL unrestrictedVector;
    BOOL arithmeticCoding;
    BOOL advancedPrediction;
    BOOL pbFrames;
};

#endif // H323_AVCODEC

#endif // __OPAL_FFH263CODEC_H


/////////////////////////////////////////////////////////////////////////////
