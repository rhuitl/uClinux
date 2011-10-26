/*
 * cu30codec.h
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
 * Contributor(s): ______________________________________.
 *                 Derek J Smithies (derek@indranet.co.nz)
 *
 * $Log: cu30codec.h,v $
 * Revision 1.6  2002/10/09 18:18:35  rogerh
 * Apply a patch from Damien Sandras
 *
 * Revision 1.5  2002/09/16 01:14:15  robertj
 * Added #define so can select if #pragma interface/implementation is used on
 *   platform basis (eg MacOS) rather than compiler, thanks Robert Monaghan.
 *
 * Revision 1.4  2002/09/03 06:19:36  robertj
 * Normalised the multi-include header prevention ifdef/define symbol.
 *
 * Revision 1.3  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.2  2002/01/16 02:53:52  dereks
 * Add methods to cope with H.245 RequestModeChange in h.261 video codec.
 *
 * Revision 1.1  2001/10/23 02:18:06  dereks
 * Initial release of CU30 video codec.
 *
 *
 */

#ifndef __OPAL_CU30CODEC_H
#define __OPAL_CU30CODEC_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif


#include "h323caps.h"


///////////////////////////////////////////////////////////////////////////////


/**This class describes the CU30 video codec capability.
 */
class H323_Cu30Capability : public H323NonStandardVideoCapability
{
  PCLASSINFO(H323_Cu30Capability, H323NonStandardVideoCapability);

  public:
  /**@name Construction */
  //@{
    /**Create a new CU30 capability.
     */
    H323_Cu30Capability(
      H323EndPoint & endpoint,   // Endpoint to get NonStandardInfo from.
      PString      statsDir,     // Directory to read statistics for codec from/to.
      INT          _width,       // width and height for the transmitter.
      INT          _height,      //
      INT          _statsFrames  // Number of frames to collect stats for.
           ); 
  //@}

  /**@name Overrides from class PObject */
  //@{
    /**Create a copy of the object.
      */
    virtual PObject * Clone() const;
  //@}

  /**@name Operations */
  //@{
    /**Create the codec instance, allocating resources as required.
     */
    virtual H323Codec * CreateCodec(
      H323Codec::Direction direction  /// Direction in which this instance runs      
    ) const;
  //@}

  /**@name Identification functions */
  //@{
    /**Get the name of the media data format this class represents.
     */
    virtual PString GetFormatName() const;
  //@}

    PString statisticsDir;  //Required by cu30 codec at initialization.
                            //directory containing stats. Good stats==good compression.

    INT      newWidth;     // width and height for the transmitter.
    INT      newHeight;    //
    INT      statsFrames;  // Number of frames to collect stats over.
};

///////////////////////////////////////////////////////////////////////////////
/**This class is a CU30 codec.
 */
class H323_Cu30Codec :  public  H323VideoCodec, public PDynaLink
{
  PCLASSINFO(H323_Cu30Codec, H323VideoCodec)

  public:
  /**@name Construction */
  //@{
    /**Create a new CU30 video codec.
     */
    H323_Cu30Codec(
      Direction direction,        /// Direction in which this instance runs
      PString   statsDir,
      INT       _width,           /// width and height for the transmitter.
      INT       _height,
      INT       _statsFrames      /// Number of frames to collect stats over.
    );
    ~H323_Cu30Codec();
  //@}


  /**@name openh323 interface routines. */
  //@{
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

       This function grabs, displays, and compresses a video frame into
       into CU30 packets.
       Get another frame if all packets of previous frame have been sent.
       Get next packet on list and send that one.
       Render the current frame if all of its packets have been sent.
     */
    virtual BOOL Read(
      BYTE * buffer,            /// Buffer of encoded data
      unsigned & length,        /// Actual length of encoded data buffer
      RTP_DataFrame & rtpFrame  /// RTP data frame
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
      const BYTE * buffer,        /// Buffer of encoded data
      unsigned length,            /// Length of encoded data buffer
      const RTP_DataFrame & rtp,  /// RTP data frame
      unsigned & written          /// Number of bytes used from data buffer
    );

    /**
       Used to acquire statistics on this frame. Used in later h323 connections for
       minimising the bits required to transmit cu30 video.
    */
    BOOL RecordStatistics(unsigned char *src);

  protected:
    /** Resize the internal variables to cope with a new frame size.
     */
    BOOL Resize(int width, int height);

    /** call RenderFrame() routine.
     */
    BOOL Redraw();

    /** Display the current frame that the encoder/decoder has in memory.        
        Takes the address of the current frame (set in last call to
         encode/decode) and then call rawDataChannel->Write().
        The current frame is in YUV420P format, and consists of 
            width*height*1.5 bytes.
        If there is no raw data channel, return true (success).
    */
    BOOL RenderFrame();

    /**Process a request for a new frame, 
       as part of the picture has been lost.

       This request is handled by causing the transmitting video
       codec to send out an intra frame. Subsequent frames will
       be inter, inter, inter,,,,, and then an intra frame.
    */
    virtual void OnLostPartialPicture();

    /**In the context of the Cu30 codec, this message means
       "Not all the statistics fields got through."
       "Please resend the statistics".
    */
    virtual void OnLostPicture();

 private:
    /*There is a problem with the CU30codec. It needs to be able to 
       carry out two tasks. 1)Grab data from the camera.
       2)Render data from an array.
       Thus, we either: two PVideoChannels, or one PVideoChannel to both
       grab and render.
       We use one PVideoChannel, which is not consistant with elsewhere,
       but enables us to (later) have a grab and display process irrespective
       of there being a H323 connection.
    */

    /**
       Close the encoder & decoder objects in the run time library.
       Delete the allocated memory for the frame buffer.
     */
    void Close();

  //@}

  /**@name cu30 interface routines. */
  //@{
    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*OpenEncoderWith)(void *, int,int,char *); 

    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*OpenEncoder)(void *, int,int);
    
    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*CloseEncoder)(void *);      
    
    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*OpenDecoder)(void *, int,int);
    
    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*CloseDecoder)(void *);      

    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*OpenStats)(void *, int,int);
    
    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*CloseStats)(void *);      
    
    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*DoEncode)(void *, unsigned char *,unsigned char **);  

    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*DoDecode)(void *, const unsigned char*, int, unsigned char **);

    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*DoStats)(void *, const unsigned char*);

    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*SetQuality)(void *, int); 

    /**
       Function pointer initialised when the plug in codec is read
     */
    int (*SetCodecSize)(void *, int,int);

    /**
       copy statistics for a particular field from the library.
    */
    int (*CopyStatsFromLib)(void *, unsigned char *dest, unsigned &length, char *field);

    /**
       copy statistics for a particular field to the library.
    */
    int (*CopyStatsToLib)(void *, unsigned char *src, unsigned length, char *field);
    
    /**When packets have been lost in the network, we need to wait for an intraframe.
       Intraframes do not depend on the previous frames. Use the test "IsIntraFrame" to
       determine if it is an intra frame.
    */
    int (*IsIntraFrame)(void *, const unsigned char *);

    /**
       If statistics have been kept on this session, save them to a directory. 
       Statistics are saved in four text files, called "y", "u", "v", and "mc"
    */
    int (*SendStatsToFiles)(void *, char *dir);


    /**
       Given a message from the remote computer, generate an intra frame.
       This occurs because the remote computer has not received all video packets.
    */
    int (*ForceIntraFrame)(void *);

    /**
       Tell the codec to create some internal data. This data is specific to this
       thread, and must not be viewed by other threads.
    */
    int (*MakeInternalData)(void **);

    /**
       Tell the codec to free the internal data. This data was created in the
       call to "MakeInternalData".
    */
    int (*FreeInternalData)(void *);

    /**
       Query the Cu30 library, and ask if the all the statistics files have
       been loaded successfully. 

       Returns 1 if everything is ready for the decoder to run.
    */
    int (*StatsLoadedOK)(void *);

      /**
       Allocate the necessary space for yuv420pImage/encodedImage, depending
       on frame size and direction. Checks for non existance of images first.
       The encoder needs just the source image. The decoder needs just the 
       soure encoded image. 

      For each Cu30 decoder created, the Cu30 decoder creates one output image.
    */
    BOOL AllocateInternalImages(void);

  //@}

    /**
       Encoder creates a memory block to hold the raw image from the grabber.
       The decoder just knows where this data is in the runtime codec.
    */
    unsigned char *yuv420pImage;     /// the rawimage, in yuv420p format.

    /**
       The encoder just knows where this data is in the runtime codec.
       The decoder uses this block of memory to assemble incoming packets 
       to form the the entire encoded image.
     */
    unsigned char *encodedImage;     /// Current image we are woring on.

    /**
       Size of the encoded image. 
     */
    int           encodedImageSize;  ///Size (in bytes) of current image.

    /**
       position in encoded image that in(out)going packets are writtten(read) to(from)
     */
    int           encodedImageIndex; ///position of next packet in encodedImage.
    
    /** 
        packetCount is used to determine if (a)need to send the statistics fields
        and (b)which field to send.
    */
    PINDEX packetCount;

    /**Codec active determines if the codec has send (or received) one packet.
   
       There are two instances of this codec. one for rx, one for tx.
       Each codec does not need to have an encoder and decoder.
       Using this variable, we prevent duplication of encoder, and the decoder.
    */
    BOOL   codecActive;

    /** the Statistics dir describes where the stats files are. These files
        provide a means for improving the compression achieved.
        The encoder remembers the old stats dir, so once set, can just use
        the OpenEncoder function, and not OpenEncoderWith().
    */
    PString statisticsDir; 

    /** For the decoder, sometimes miss incoming video packets. In this case, cannot 
	keep going and hope. Consequently, we wait, until we get a frame that does not
	depend on the previous frame. Thus, we wait for an IntraFrame.
    */
    BOOL waitForIntraFrame;

    /**
       During the current video connection, record the statistics for N frames.
       These statistics are saved, and used in subsequent video connections. By taking 
       statistics, we can optimise the compression ratio next time a connection occurs.
    */
    INT  statsFrames;

    /**
       Advises transmitting video codec that the statistics frames need to be resent.
       This boolean is set true in response to a On_lostPicture H245 Message.
    */
    BOOL resendStats;

    /**
       Pointer to the internal data used by the codec library.
     */
    void  *internData;
};


#endif // __OPAL_CU30CODEC_H


/////////////////////////////////////////////////////////////////////////////
