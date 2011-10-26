/*
 * mediafmt.cxx
 *
 * Media Format descriptions
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
 *
 * $Log: mediafmt.cxx,v $
 * Revision 1.29  2005/01/11 07:12:13  csoutheren
 * Fixed namespace collisions with plugin starup factories
 *
 * Revision 1.28  2005/01/04 12:20:12  csoutheren
 * Fixed more problems with global statics
 *
 * Revision 1.27  2004/06/30 12:31:16  rjongbloed
 * Rewrite of plug in system to use single global variable for all factories to avoid all sorts
 *   of issues with startup orders and Windows DLL multiple instances.
 *
 * Revision 1.26  2004/06/18 03:06:00  csoutheren
 * Changed dynamic payload type allocation code to avoid needless renumbering of
 * media formats when new formats are created
 *
 * Revision 1.25  2004/06/18 02:24:46  csoutheren
 * Fixed allocation of dynamic RTP payload types as suggested by Guilhem Tardy
 *
 * Revision 1.24  2004/06/03 13:32:01  csoutheren
 * Renamed INSTANTIATE_FACTORY
 *
 * Revision 1.23  2004/06/03 12:48:35  csoutheren
 * Decomposed PFactory declarations to hopefully avoid problems with DLLs
 *
 * Revision 1.22  2004/06/01 05:50:32  csoutheren
 * Increased usage of typedef'ed factory rather than redefining
 *
 * Revision 1.21  2004/05/23 12:49:34  rjongbloed
 * Tidied some of the OpalMediaFormat usage after abandoning some previous
 *   code due to MSVC6 compiler bug.
 *
 * Revision 1.20  2004/05/20 02:07:29  csoutheren
 * Use macro to work around MSVC internal compiler errors
 *
 * Revision 1.19  2004/05/19 09:48:35  csoutheren
 * Fixed problem with non-RTP media formats causing endless loops
 *
 * Revision 1.18  2004/05/19 07:38:24  csoutheren
 * Changed OpalMediaFormat handling to use abstract factory method functions
 *
 * Revision 1.17  2004/05/05 09:40:05  csoutheren
 * OpalMediaFormat.Clone() does not exist - use copy constructor instead
 *
 * Revision 1.16  2004/05/03 00:52:24  csoutheren
 * Fixed problem with OpalMediaFormat::GetMediaFormatsList
 * Added new version of OpalMediaFormat::GetMediaFormatsList that minimses copying
 *
 * Revision 1.15  2004/04/03 10:38:25  csoutheren
 * Added in initial cut at codec plugin code. Branches are for wimps :)
 *
 * Revision 1.14.2.1  2004/03/31 11:11:59  csoutheren
 * Initial public release of plugin codec code
 *
 * Revision 1.14  2004/02/26 23:41:22  csoutheren
 * Fixed multi-threading problem
 *
 * Revision 1.13  2004/02/26 11:45:44  csoutheren
 * Fixed problem with OpalMediaFormat failing incorrect reason
 *
 * Revision 1.12  2004/02/26 08:19:32  csoutheren
 * Fixed threading problem with GetMediaFormatList
 *
 * Revision 1.11  2002/12/03 09:20:01  craigs
 * Fixed problem with RFC2833 and a dynamic RTP type using the same RTP payload number
 *
 * Revision 1.10  2002/12/02 03:06:26  robertj
 * Fixed over zealous removal of code when NO_AUDIO_CODECS set.
 *
 * Revision 1.9  2002/10/30 05:54:17  craigs
 * Fixed compatibilty problems with G.723.1 6k3 and 5k3
 *
 * Revision 1.8  2002/08/05 10:03:48  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.7  2002/06/25 08:30:13  robertj
 * Changes to differentiate between stright G.723.1 and G.723.1 Annex A using
 *   the OLC dataType silenceSuppression field so does not send SID frames
 *   to receiver codecs that do not understand them.
 *
 * Revision 1.6  2002/01/22 07:08:26  robertj
 * Added IllegalPayloadType enum as need marker for none set
 *   and MaxPayloadType is a legal value.
 *
 * Revision 1.5  2001/12/11 04:27:28  craigs
 * Added support for 5.3kbps G723.1
 *
 * Revision 1.4  2001/09/21 02:51:45  robertj
 * Implemented static object for all "known" media formats.
 * Added default session ID to media format description.
 *
 * Revision 1.3  2001/05/11 04:43:43  robertj
 * Added variable names for standard PCM-16 media format name.
 *
 * Revision 1.2  2001/02/09 05:13:56  craigs
 * Added pragma implementation to (hopefully) reduce the executable image size
 * under Linux
 *
 * Revision 1.1  2001/01/25 07:27:16  robertj
 * Major changes to add more flexible OpalMediaFormat class to normalise
 *   all information about media types, especially codecs.
 *
 */

#include <ptlib.h>

#ifdef __GNUC__
#pragma implementation "mediafmt.h"
#endif

#include "mediafmt.h"
#include "rtp.h"
#include "h323pluginmgr.h"

namespace PWLibStupidLinkerHacks {
  extern int h323Loader;
};

static class PMediaFormatInstantiateMe
{
  public:
    PMediaFormatInstantiateMe()
    { PWLibStupidLinkerHacks::h323Loader = 1; }
} instance;

/////////////////////////////////////////////////////////////////////////////

char OpalPCM16[] = OPAL_PCM16;

OPAL_MEDIA_FORMAT_DECLARE(OpalPCM16Format, 
          OpalPCM16,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::L16_Mono,
          TRUE,   // Needs jitter
          128000, // bits/sec
          16, // bytes/frame
          8, // 1 millisecond
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG711uLaw64k[] = OPAL_G711_ULAW_64K;

OPAL_MEDIA_FORMAT_DECLARE(OpalG711uLaw64kFormat,
          OpalG711uLaw64k,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::PCMU,
          TRUE,   // Needs jitter
          64000, // bits/sec
          8, // bytes/frame
          8, // 1 millisecond/frame
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG711ALaw64k[] = OPAL_G711_ALAW_64K;

OPAL_MEDIA_FORMAT_DECLARE(OpalG711ALaw64kFormat,
          OpalG711ALaw64k,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::PCMA,
          TRUE,   // Needs jitter
          64000, // bits/sec
          8, // bytes/frame
          8, // 1 millisecond/frame
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG728[] = OPAL_G728;

OPAL_MEDIA_FORMAT_DECLARE(OpalG728Format,
          OpalG728,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G728,
          TRUE, // Needs jitter
          16000,// bits/sec
          5,    // bytes
          20,   // 2.5 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG729[] = OPAL_G729;

OPAL_MEDIA_FORMAT_DECLARE(OpalG729Format,
          OpalG729,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G729,
          TRUE, // Needs jitter
          8000, // bits/sec
          10,   // bytes
          80,   // 10 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG729A[] = OPAL_G729A;

OPAL_MEDIA_FORMAT_DECLARE(OpalG729AFormat,
          OpalG729A,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G729,
          TRUE, // Needs jitter
          8000, // bits/sec
          10,   // bytes
          80,   // 10 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG729B[] = OPAL_G729B;

OPAL_MEDIA_FORMAT_DECLARE(OpalG729BFormat,
          OpalG729B,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G729,
          TRUE, // Needs jitter
          8000, // bits/sec
          10,   // bytes
          80,   // 10 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG729AB[] = OPAL_G729AB;

OPAL_MEDIA_FORMAT_DECLARE(OpalG729ABFormat,
          OpalG729AB,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G729,
          TRUE, // Needs jitter
          8000, // bits/sec
          10,   // bytes
          80,   // 10 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG7231_6k3[] = OPAL_G7231_6k3;

OPAL_MEDIA_FORMAT_DECLARE(OpalG7231_6k3Format,
          OpalG7231_6k3,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G7231,
          TRUE, // Needs jitter
          6400, // bits/sec
          24,   // bytes
          240,  // 30 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG7231_5k3[] = OPAL_G7231_5k3;

OPAL_MEDIA_FORMAT_DECLARE(OpalG7231_5k3Format,
          OpalG7231_5k3,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G7231,
          TRUE, // Needs jitter
          5300, // bits/sec
          24,   // bytes
          240,  // 30 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG7231A_6k3[] = OPAL_G7231A_6k3;

OPAL_MEDIA_FORMAT_DECLARE(OpalG7231A_6k3Format,
          OpalG7231A_6k3,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G7231,
          TRUE, // Needs jitter
          6400, // bits/sec
          24,   // bytes
          240,  // 30 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalG7231A_5k3[] = OPAL_G7231A_5k3;

OPAL_MEDIA_FORMAT_DECLARE(OpalG7231A_5k3Format,
          OpalG7231A_5k3,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::G7231,
          TRUE, // Needs jitter
          5300, // bits/sec
          24,   // bytes
          240,  // 30 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalGSM0610[] = OPAL_GSM0610;

OPAL_MEDIA_FORMAT_DECLARE(OpalGSM0610Format,
          OpalGSM0610,
          OpalMediaFormat::DefaultAudioSessionID,
          RTP_DataFrame::GSM,
          TRUE,  // Needs jitter
          13200, // bits/sec
          33,    // bytes
          160,   // 20 milliseconds
          OpalMediaFormat::AudioTimeUnits,
          0)

/////////////////////////////////////////////////////////////////////////////

char OpalT120[] = "T.120";

OPAL_MEDIA_FORMAT_DECLARE(OpalT120Format,
          OpalT120,
          OpalMediaFormat::DefaultDataSessionID,
          RTP_DataFrame::IllegalPayloadType,
          FALSE,   // No jitter for data
          825000,   // 100's bits/sec
          0,0,0,0)

/////////////////////////////////////////////////////////////////////////////


OpalMediaFormat::OpalMediaFormat()
{
  rtpPayloadType = RTP_DataFrame::IllegalPayloadType;

  needsJitter = FALSE;
  bandwidth = 0;
  frameSize = 0;
  frameTime = 0;
  timeUnits = 0;
  codecBaseTime = 0;
  defaultSessionID = 0;
}


OpalMediaFormat::OpalMediaFormat(const char * search, BOOL exact)
{
  rtpPayloadType = RTP_DataFrame::IllegalPayloadType;

  needsJitter = FALSE;
  bandwidth = 0;
  frameSize = 0;
  frameTime = 0;
  timeUnits = 0;
  codecBaseTime = 0;
  defaultSessionID = 0; 

  // look for the media type in the factory. 
  // Don't make a copy of the list - lock the list and use the raw data
  if (exact) {
    OpalMediaFormat * registeredFormat = OpalMediaFormatFactory::CreateInstance(search);
    if (registeredFormat != NULL)
      *this = *registeredFormat;
  }
  else {
    PWaitAndSignal m(OpalMediaFormatFactory::GetMutex());
    OpalMediaFormatFactory::KeyMap_T & keyMap = OpalMediaFormatFactory::GetKeyMap();
    OpalMediaFormatFactory::KeyMap_T::const_iterator r;
    for (r = keyMap.begin(); r != keyMap.end(); ++r) {
      if (r->first.Find(search) != P_MAX_INDEX) {
        *this = *OpalMediaFormatFactory::CreateInstance(r->first);
        break;
      }
    }
  }
}


OpalMediaFormat::OpalMediaFormat(const char * fullName,
                                 unsigned dsid,
                                 RTP_DataFrame::PayloadTypes pt,
                                 BOOL     nj,
                                 unsigned bw,
                                 PINDEX   fs,
                                 unsigned ft,
                                 unsigned tu,
                                 time_t ts)
  : PCaselessString(fullName)
{
  rtpPayloadType = pt;
  defaultSessionID = dsid;
  needsJitter = nj;
  bandwidth = bw;
  frameSize = fs;
  frameTime = ft;
  timeUnits = tu;
  codecBaseTime = ts;

  // assume non-dynamic payload types are correct and do not need deconflicting
  if (rtpPayloadType < RTP_DataFrame::DynamicBase || rtpPayloadType == RTP_DataFrame::IllegalPayloadType)
    return;

  // find the next unused dynamic number, and find anything with the new 
  // rtp payload type if it is explicitly required
  PWaitAndSignal m(OpalMediaFormatFactory::GetMutex());
  OpalMediaFormatFactory::KeyMap_T & keyMap = OpalMediaFormatFactory::GetKeyMap();

  OpalMediaFormat * match = NULL;
  RTP_DataFrame::PayloadTypes nextUnused = RTP_DataFrame::DynamicBase;
  OpalMediaFormatFactory::KeyMap_T::iterator r;

  do {
    for (r = keyMap.begin(); r != keyMap.end(); ++r) {
      if (r->first == fullName)
        continue;
      OpalMediaFormat & fmt = *OpalMediaFormatFactory::CreateInstance(r->first);
      if (fmt.GetPayloadType() == nextUnused) {
        nextUnused = (RTP_DataFrame::PayloadTypes)(nextUnused + 1);
        break; // restart the search
      }
      if (fmt.GetPayloadType() == rtpPayloadType)
        match = &fmt;
    }
  } while (r != keyMap.end());

  // If we found a match to the payload type, then it needs to be deconflicted
  // If the new format is just requesting any dynamic payload number, then give it the next unused one
  // If it is requesting a specific code (like RFC 2833) then renumber the old format. This could be dangerous
  // as media formats could be created when there is a session in use with the old media format and payload type
  // For this reason, any media formats that require specific dynamic codes should be created before any calls are made
  if (match != NULL) {
    if (rtpPayloadType == RTP_DataFrame::DynamicBase)
      rtpPayloadType = nextUnused;
    else 
      match->rtpPayloadType = nextUnused;
  }
}


void OpalMediaFormat::GetRegisteredMediaFormats(OpalMediaFormat::List & list)
{
  list.DisallowDeleteObjects();
  PWaitAndSignal m(OpalMediaFormatFactory::GetMutex());
  OpalMediaFormatFactory::KeyMap_T & keyMap = OpalMediaFormatFactory::GetKeyMap();
  OpalMediaFormatFactory::KeyMap_T::const_iterator r;
  for (r = keyMap.begin(); r != keyMap.end(); ++r)
    list.Append(OpalMediaFormatFactory::CreateInstance(r->first));
}


OpalMediaFormat::List OpalMediaFormat::GetRegisteredMediaFormats()
{
  OpalMediaFormat::List list;
  GetRegisteredMediaFormats(list);
  return list;
}


// End of File ///////////////////////////////////////////////////////////////
