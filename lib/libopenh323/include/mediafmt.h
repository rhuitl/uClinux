/*
 * mediafmt.h
 *
 * Media Format descriptions
 *
 * Open H323 Library
 *
 * Copyright (c) 1998-2001 Equivalence Pty. Ltd.
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
 *
 * $Log: mediafmt.h,v $
 * Revision 1.24  2005/11/30 13:05:01  csoutheren
 * Changed tags for Doxygen
 *
 * Revision 1.23  2005/08/13 19:35:57  shorne
 * Fix compile error on MSVC6
 *
 * Revision 1.22  2004/07/07 08:04:54  csoutheren
 * Added video codecs to default codec list, but H.263 is only loaded if the .so/DLL is found
 *
 * Revision 1.21  2004/07/07 03:52:12  csoutheren
 * Fixed incorrect strings returned by GetFormatName on G.711 codecs
 *
 * Revision 1.20  2004/06/30 12:31:09  rjongbloed
 * Rewrite of plug in system to use single global variable for all factories to avoid all sorts
 *   of issues with startup orders and Windows DLL multiple instances.
 *
 * Revision 1.19  2004/05/23 12:49:20  rjongbloed
 * Tidied some of the OpalMediaFormat usage after abandoning some previous
 *   code due to MSVC6 compiler bug.
 *
 * Revision 1.18  2004/05/20 02:07:28  csoutheren
 * Use macro to work around MSVC internal compiler errors
 *
 * Revision 1.17  2004/05/19 07:38:22  csoutheren
 * Changed OpalMediaFormat handling to use abstract factory method functions
 *
 * Revision 1.16  2004/05/03 00:52:23  csoutheren
 * Fixed problem with OpalMediaFormat::GetMediaFormatsList
 * Added new version of OpalMediaFormat::GetMediaFormatsList that minimses copying
 *
 * Revision 1.15  2004/04/03 10:38:24  csoutheren
 * Added in initial cut at codec plugin code. Branches are for wimps :)
 *
 * Revision 1.14.2.1  2004/03/31 11:11:59  csoutheren
 * Initial public release of plugin codec code
 *
 * Revision 1.14  2004/02/26 08:19:31  csoutheren
 * Fixed threading problem with GetMediaFormatList
 *
 * Revision 1.13  2002/12/02 03:06:26  robertj
 * Fixed over zealous removal of code when NO_AUDIO_CODECS set.
 *
 * Revision 1.12  2002/09/16 01:14:15  robertj
 * Added #define so can select if #pragma interface/implementation is used on
 *   platform basis (eg MacOS) rather than compiler, thanks Robert Monaghan.
 *
 * Revision 1.11  2002/09/03 06:19:37  robertj
 * Normalised the multi-include header prevention ifdef/define symbol.
 *
 * Revision 1.10  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.9  2002/06/25 08:30:08  robertj
 * Changes to differentiate between stright G.723.1 and G.723.1 Annex A using
 *   the OLC dataType silenceSuppression field so does not send SID frames
 *   to receiver codecs that do not understand them.
 *
 * Revision 1.8  2002/03/21 02:39:15  robertj
 * Added backward compatibility define
 *
 * Revision 1.7  2002/02/11 04:15:56  robertj
 * Put G.723.1 at 6.3kbps back to old string value of "G.723.1" to improve
 *   backward compatibility. New #define is a synonym for it.
 *
 * Revision 1.6  2002/01/22 07:08:26  robertj
 * Added IllegalPayloadType enum as need marker for none set
 *   and MaxPayloadType is a legal value.
 *
 * Revision 1.5  2001/12/11 04:27:50  craigs
 * Added support for 5.3kbps G723.1
 *
 * Revision 1.4  2001/09/21 02:49:44  robertj
 * Implemented static object for all "known" media formats.
 * Added default session ID to media format description.
 *
 * Revision 1.3  2001/05/11 04:43:41  robertj
 * Added variable names for standard PCM-16 media format name.
 *
 * Revision 1.2  2001/02/09 05:16:24  robertj
 * Added #pragma interface for GNU C++.
 *
 * Revision 1.1  2001/01/25 07:27:14  robertj
 * Major changes to add more flexible OpalMediaFormat class to normalise
 *   all information about media types, especially codecs.
 *
 */

#ifndef __OPAL_MEDIAFMT_H
#define __OPAL_MEDIAFMT_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif


#include "rtp.h"


///////////////////////////////////////////////////////////////////////////////

/**This class describes a media format as used in the OPAL system. A media
   format is the type of any media data that is trasferred between OPAL
   entities. For example an audio codec such as G.723.1 is a media format, a
   video codec such as H.261 is also a media format.
  */
class OpalMediaFormat : public PCaselessString
{
  PCLASSINFO(OpalMediaFormat, PCaselessString);

  public:
    PLIST(List, OpalMediaFormat);

    /**Default constructor creates a PCM-16 media format.
      */
    OpalMediaFormat();

    /**A constructor that only has a string name will search through the
       RegisteredMediaFormats list for the full specification so the other
       information fields can be set from the database.
      */
    OpalMediaFormat(
      const char * search,  ///<  Name to search for
      BOOL exact = TRUE     ///<  Flag for if search is to match name exactly
    );

    /**Return TRUE if media format info is valid. This may be used if the
       single string constructor is used to check that it matched something
       in the registered media formats database.
      */
    BOOL IsValid() const { return rtpPayloadType <= RTP_DataFrame::MaxPayloadType; }

    /**Get the RTP payload type that is to be used for this media format.
       This will either be an intrinsic one for the media format eg GSM or it
       will be automatically calculated as a dynamic media format that will be
       uniqueue amongst the registered media formats.
      */
    RTP_DataFrame::PayloadTypes GetPayloadType() const { return rtpPayloadType; }

    enum {
      DefaultAudioSessionID = 1,
      DefaultVideoSessionID = 2,
      DefaultDataSessionID  = 3
    };

    /**Get the default session ID for media format.
      */
    unsigned GetDefaultSessionID() const { return defaultSessionID; }

    /**Determine if the media format requires a jitter buffer. As a rule an
       audio codec needs a jitter buffer and all others do not.
      */
    BOOL NeedsJitterBuffer() const { return needsJitter; }

    /**Get the average bandwidth used in bits/second.
      */
    unsigned GetBandwidth() const { return bandwidth; }

    /**Get the maximum frame size in bytes. If this returns zero then the
       media format has no intrinsic maximum frame size, eg G.711 would 
       return zero but G.723.1 whoud return 24.
      */
    PINDEX GetFrameSize() const { return frameSize; }

    /**Get the frame rate in RTP timestamp units. If this returns zero then
       the media format is not real time and has no intrinsic timing eg
      */
    unsigned GetFrameTime() const { return frameTime; }

    /**Get the number of RTP timestamp units per millisecond.
      */
    unsigned GetTimeUnits() const { return timeUnits; }

    enum StandardTimeUnits {
      AudioTimeUnits = 8,  ///<  8kHz sample rate
      VideoTimeUnits = 90  ///<  90kHz sample rate
    };

    /**Get the list of media formats that have been registered.
      */
    static List GetRegisteredMediaFormats();
    static void GetRegisteredMediaFormats(List & list);

    friend class OpalStaticMediaFormat;

    /**This form of the constructor will register the full details of the
       media format into an internal database. This would typically be used
       as a static global. In fact it would be very dangerous for an instance
       to use this constructor in any other way, especially local variables.

       If the rtpPayloadType is RTP_DataFrame::DynamicBase, then the RTP
       payload type is actually set to teh first unused dynamic RTP payload
       type that is in the registers set of media formats.

       The frameSize parameter indicates that the media format has a maximum
       size for each data frame, eg G.723.1 frames are no more than 24 bytes
       long. If zero then there is no intrinsic maximum, eg G.711.
      */
    OpalMediaFormat(
      const char * fullName,  ///<  Full name of media format
      unsigned defaultSessionID,  ///<  Default session for codec type
      RTP_DataFrame::PayloadTypes rtpPayloadType, ///<  RTP payload type code
      BOOL     needsJitter,   ///<  Indicate format requires a jitter buffer
      unsigned bandwidth,     ///<  Bandwidth in bits/second
      PINDEX   frameSize = 0, ///<  Size of frame in bytes (if applicable)
      unsigned frameTime = 0, ///<  Time for frame in RTP units (if applicable)
      unsigned timeUnits = 0, ///<  RTP units for frameTime (if applicable)
      time_t timeStamp = 0    ///<  timestamp (for versioning)
    );
  protected:
    RTP_DataFrame::PayloadTypes rtpPayloadType;
    unsigned defaultSessionID;
    BOOL     needsJitter;
    unsigned bandwidth;
    PINDEX   frameSize;
    unsigned frameTime;
    unsigned timeUnits;
    time_t codecBaseTime;
};


// List of known media formats

#define OPAL_PCM16         "PCM-16"
#define OPAL_G711_ULAW_64K "G.711-uLaw-64k"
#define OPAL_G711_ALAW_64K "G.711-ALaw-64k"
#define OPAL_G711_ULAW_56K "G.711-uLaw-56k"
#define OPAL_G711_ALAW_56K "G.711-ALaw-56k"
#define OPAL_G728          "G.728"
#define OPAL_G729          "G.729"
#define OPAL_G729A         "G.729A"
#define OPAL_G729B         "G.729B"
#define OPAL_G729AB        "G.729A/B"
#define OPAL_G7231         "G.723.1"
#define OPAL_G7231_6k3     OPAL_G7231
#define OPAL_G7231_5k3     "G.723.1(5.3k)"
#define OPAL_G7231A_6k3    "G.723.1A(6.3k)"
#define OPAL_G7231A_5k3    "G.723.1A(5.3k)"
#define OPAL_GSM0610       "GSM-06.10"

extern char OpalPCM16[];
extern char OpalG711uLaw64k[];
extern char OpalG711ALaw64k[];
extern char OpalG728[];
extern char OpalG729[];
extern char OpalG729A[];
extern char OpalG729B[];
extern char OpalG729AB[];
extern char OpalG7231_6k3[];
extern char OpalG7231_5k3[];
extern char OpalG7231A_6k3[];
extern char OpalG7231A_5k3[];
extern char OpalGSM0610[];

#define OpalG711uLaw      OpalG711uLaw64k
#define OpalG711ALaw      OpalG711ALaw64k
#define OpalG7231 OpalG7231_6k3

//
// Originally, the following inplace code was used instead of this macro:
//
// static PAbstractSingletonFactory<OpalMediaFormat, 
//     OpalStaticMediaFormatTemplate<
//          OpalPCM16,
//          OpalMediaFormat::DefaultAudioSessionID,
//          RTP_DataFrame::L16_Mono,
//          TRUE,   // Needs jitter
//          128000, // bits/sec
//          16, // bytes/frame
//          8, // 1 millisecond
//          OpalMediaFormat::AudioTimeUnits,
//          0
//     > 
// > opalPCM16Factory(OpalPCM16);
//
// This used the following macro:
//
//
//  template <
//        const char * _fullName,  /// Full name of media format
//        unsigned _defaultSessionID,  /// Default session for codec type
//        RTP_DataFrame::PayloadTypes _rtpPayloadType, /// RTP payload type code
//        BOOL     _needsJitter,       /// Indicate format requires a jitter buffer
//        unsigned _bandwidth,         /// Bandwidth in bits/second
//        PINDEX   _frameSize,         /// Size of frame in bytes (if applicable)
//        unsigned _frameTime,         /// Time for frame in RTP units (if applicable)
//        unsigned _timeUnits,         /// RTP units for frameTime (if applicable)
//        time_t _timeStamp            /// timestamp (for versioning)
//  >
//  class OpalStaticMediaFormatTemplate : public OpalStaticMediaFormat
//  {
//    public:
//      OpalStaticMediaFormatTemplate()
//        : OpalStaticMediaFormat(_fullName, _defaultSessionID, _rtpPayloadType, _needsJitter, _bandwidth
//        , _frameSize, _frameTime, _timeUnits, _timeStamp )
//      { }
//  };
//
// Unfortauntely, MSVC 6 did not like this so this crappy macro has to be used instead of a template
//

typedef PFactory<OpalMediaFormat> OpalMediaFormatFactory;

#define OPAL_MEDIA_FORMAT_DECLARE(classname, _fullName, _defaultSessionID, _rtpPayloadType, _needsJitter,_bandwidth, _frameSize, _frameTime, _timeUnits, _timeStamp) \
class classname : public OpalMediaFormat \
{ \
  public: \
    classname() \
      : OpalMediaFormat(_fullName, _defaultSessionID, _rtpPayloadType, _needsJitter, _bandwidth, \
        _frameSize, _frameTime, _timeUnits, _timeStamp){} \
}; \
OpalMediaFormatFactory::Worker<classname> classname##Factory(_fullName, true); \


#endif  // __OPAL_MEDIAFMT_H


// End of File ///////////////////////////////////////////////////////////////
