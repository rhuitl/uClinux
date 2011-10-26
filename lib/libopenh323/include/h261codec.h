/*
 * h261codec.h
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
 * Contributor(s): Michele Piccini (michele@piccini.com).
 *                 Derek Smithies (derek@indranet.co.nz)
 *
 * $Log: h261codec.h,v $
 * Revision 1.37  2006/03/28 05:15:01  csoutheren
 * Change video codecs to set grabber capture size rather than
 * grabber size setting codec size
 *
 * Revision 1.36  2005/11/30 13:05:01  csoutheren
 * Changed tags for Doxygen
 *
 * Revision 1.35  2004/01/02 00:31:42  dereksmithies
 * Fix test on presence/absence of video.
 *
 * Revision 1.34  2003/12/14 10:42:29  rjongbloed
 * Changes for compilability without video support.
 *
 * Revision 1.33  2003/10/02 23:37:56  dereksmithies
 * Add fix for fast update problem in h261 codec. Thanks to Martin André for doing the initial legwork.
 *
 * Revision 1.32  2003/04/03 23:54:11  robertj
 * Added fast update to H.261 codec, thanks Gustavo García Bernardo
 *
 * Revision 1.31  2002/12/16 09:11:15  robertj
 * Added new video bit rate control, thanks Walter H. Whitlock
 *
 * Revision 1.30  2002/09/16 01:14:15  robertj
 * Added #define so can select if #pragma interface/implementation is used on
 *   platform basis (eg MacOS) rather than compiler, thanks Robert Monaghan.
 *
 * Revision 1.29  2002/09/03 06:19:36  robertj
 * Normalised the multi-include header prevention ifdef/define symbol.
 *
 * Revision 1.28  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.27  2002/01/09 06:06:37  robertj
 * Fixed setting of RTP timestamp values on video transmission.
 *
 * Revision 1.26  2002/01/09 00:21:36  robertj
 * Changes to support outgoing H.245 RequstModeChange.
 *
 * Revision 1.25  2001/12/04 04:26:03  robertj
 * Added code to allow change of video quality in H.261, thanks Damian Sandras
 *
 * Revision 1.24  2001/10/23 02:18:06  dereks
 * Initial release of CU30 video codec.
 *
 * Revision 1.23  2001/09/25 03:14:47  dereks
 * Add constant bitrate control for the h261 video codec.
 * Thanks Tiziano Morganti for the code to set bit rate. Good work!
 *
 * Revision 1.22  2001/05/25 01:10:26  dereks
 * Remove unnecessary packet receive variable.
 * Alter the position of the check for change in frame size.
 *
 * Revision 1.21  2001/02/09 05:16:24  robertj
 * Added #pragma interface for GNU C++.
 *
 * Revision 1.20  2001/01/25 07:27:14  robertj
 * Major changes to add more flexible OpalMediaFormat class to normalise
 *   all information about media types, especially codecs.
 *
 * Revision 1.19  2000/12/19 22:33:44  dereks
 * Adjust so that the video channel is used for reading/writing raw video
 * data, which better modularizes the video codec.
 *
 * Revision 1.18  2000/08/21 04:45:06  dereks
 * Fix dangling pointer that caused segfaults for windows&unix users.
 * Improved the test image which is used when video grabber won't open.
 * Added code to handle setting of video Tx Quality.
 * Added code to set the number of background blocks sent with every frame.
 *
 * Revision 1.17  2000/07/04 13:00:36  craigs
 * Fixed problem with selecting large and small video sizes
 *
 * Revision 1.16  2000/05/18 11:53:33  robertj
 * Changes to support doc++ documentation generation.
 *
 * Revision 1.15  2000/05/10 04:05:26  robertj
 * Changed capabilities so has a function to get name of codec, instead of relying on PrintOn.
 *
 * Revision 1.14  2000/05/02 04:32:24  robertj
 * Fixed copyright notice comment.
 *
 * Revision 1.13  2000/03/30 23:10:50  robertj
 * Fixed error in comments regarding GetFramerate() function.
 *
 * Revision 1.12  2000/03/21 03:06:47  robertj
 * Changes to make RTP TX of exact numbers of frames in some codecs.
 *
 * Revision 1.11  2000/02/04 05:00:08  craigs
 * Changes for video transmission
 *
 * Revision 1.10  2000/01/13 04:03:45  robertj
 * Added video transmission
 *
 * Revision 1.9  1999/12/23 23:02:34  robertj
 * File reorganision for separating RTP from H.323 and creation of LID for VPB support.
 *
 * Revision 1.8  1999/11/29 08:59:56  craigs
 * Added new stuff for new video codec interface
 *
 * Revision 1.7  1999/11/01 00:52:00  robertj
 * Fixed various problems in video, especially ability to pass error return value.
 *
 * Revision 1.6  1999/10/08 09:59:02  robertj
 * Rewrite of capability for sending multiple audio frames
 *
 * Revision 1.5  1999/10/08 04:58:37  robertj
 * Added capability for sending multiple audio frames in single RTP packet
 *
 * Revision 1.4  1999/09/21 14:03:41  robertj
 * Changed RTP data frame parameter in Write() to be const.
 *
 * Revision 1.3  1999/09/21 08:12:50  craigs
 * Added support for video codecs and H261
 *
 * Revision 1.2  1999/09/18 13:27:24  craigs
 * Added ability disable jitter buffer for codecs
 * Added ability to access entire RTP frame from codec Write
 *
 * Revision 1.1  1999/09/08 04:05:48  robertj
 * Added support for video capabilities & codec, still needs the actual codec itself!
 *
 */

#ifndef __OPAL_H261CODEC_H
#define __OPAL_H261CODEC_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif


#include "h323caps.h"

#ifndef NO_H323_VIDEO


class P64Decoder;
class P64Encoder;



///////////////////////////////////////////////////////////////////////////////

/**This class is a H.261 video capability.
 */
class H323_H261Capability : public H323VideoCapability
{
  PCLASSINFO(H323_H261Capability, H323VideoCapability)

  public:
  /**@name Construction */
  //@{
    /**Create a new H261 Capability
     */
    H323_H261Capability(
      unsigned qcifMPI,
      unsigned cifMPI,
      BOOL temporalSpatialTradeOffCapability = TRUE,
      BOOL stillImageTransmission = FALSE,
      unsigned maxBitRate = 850
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

    /** Get temporal/spatial tradeoff capabilty
     */
    BOOL GetTemporalSpatialTradeOffCapability() const
      { return temporalSpatialTradeOffCapability; }

    /** Get still image transmission flag
     */
    BOOL GetStillImageTransmission() const
      { return stillImageTransmission; }

    /** Get maximum bit rate
     */
    unsigned GetMaxBitRate() const
      { return maxBitRate; }

    /** Get qcifMPI
     */
    unsigned GetQCIFMPI() const
      { return qcifMPI; }

    /** Get cifMPI
     */
    unsigned GetCIFMPI() const
      { return cifMPI; }

  //@}

  protected:
    unsigned qcifMPI;                   // 1..4 units 1/29.97 Hz
    unsigned cifMPI;                    // 1..4 units 1/29.97 Hz
    BOOL     temporalSpatialTradeOffCapability;
    unsigned maxBitRate;                // units of 100 bit/s
    BOOL     stillImageTransmission;    // Annex D of H.261
};


/**This class is a H.261 video codec.
 */
class H323_H261Codec : public H323VideoCodec
{
  PCLASSINFO(H323_H261Codec, H323VideoCodec)

  public:
    /**Create a new H261 video codec
     */
    H323_H261Codec(
      Direction direction,        ///< Direction in which this instance runs
      BOOL isqCIF
    );
    ~H323_H261Codec();

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
      BYTE * buffer,            ///< Buffer of encoded data
      unsigned & length,        ///< Actual length of encoded data buffer
      RTP_DataFrame & rtpFrame  ///< RTP data frame
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
      const BYTE * buffer,        ///< Buffer of encoded data
      unsigned length,            ///< Length of encoded data buffer
      const RTP_DataFrame & rtp,  ///< RTP data frame
      unsigned & written          ///< Number of bytes used from data buffer
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
 
    /**Minimum quality limit for the transmitted video.
     * Default is 1.  Encode quality will not be set below this value.
     */
    void SetTxMinQuality(int qlevel);

    /**Maximum quality limit for the transmitted video.
     * Default is 24.  Encode quality will not be set above this value.
     */
    void SetTxMaxQuality(int qlevel);

    /**Set the number of blocks in the background that need
       to be transmitted with each frame
    */
    void SetBackgroundFill(int fillLevel);

    /**Process a FastUpdatePicture command from remote endpoint.
       The default behaviour does nothing.
     */
    virtual void OnFastUpdatePicture();

    /**Process a request for a new frame, 
       as part of the picture has been lost.
    */
    virtual void OnLostPartialPicture();

    /**Process a request for a new frame, 
       as all of the picture has been lost.
    */
    virtual void OnLostPicture();

    ////////////////////////////////////////////////////////////////
    //There is a problem with the H261codec. It needs to be able to 
    //carry out two tasks. 1)Grab data from the camera.
    //2)Render data from an array.
    //Thus, we either: two PVideoChannels, or one PVideoChannel to both
    //grab and render.
    //We use one PVideoChannel, which is not consistant with elsewhere,
    //but enables us to (later) have a grab and display process irrespective
    //of there being a H323 connection.


  protected:
    BOOL Resize(int width, int height);
    BOOL Redraw();
    BOOL RenderFrame();

    BOOL doFastUpdate;
    PMutex fastUpdateMutex;

    P64Decoder       * videoDecoder;
    P64Encoder       * videoEncoder;

    int now;
    BYTE * rvts;
    int ndblk, nblk;
    unsigned timestampDelta;
    BOOL isqCIF;
};


#endif // __OPAL_H261CODEC_H


#endif // NO_H323_VIDEO


/////////////////////////////////////////////////////////////////////////////
