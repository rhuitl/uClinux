/*
 * main.cxx
 *
 * A simple H.323 "net telephone" application.
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
 * The Original Code is Open H323
 *
 * The Initial Developer of the Original Code is Post Increment
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: main.cxx,v $
 * Revision 1.13  2005/07/23 01:54:47  rjongbloed
 * Fixed some compiler warnings
 *
 * Revision 1.12  2004/08/26 08:05:03  csoutheren
 * Codecs now appear in abstract factory system
 * Fixed Windows factory bootstrap system (again)
 *
 * Revision 1.11  2004/06/30 12:31:09  rjongbloed
 * Rewrite of plug in system to use single global variable for all factories to avoid all sorts
 *   of issues with startup orders and Windows DLL multiple instances.
 *
 * Revision 1.10  2004/06/18 02:25:15  csoutheren
 * Added display of RTP payload types to media format display
 *
 * Revision 1.9  2004/06/15 10:12:07  csoutheren
 * Added -C option
 *
 * Revision 1.8  2004/06/01 05:53:51  csoutheren
 * Added option to show list of registered capabilities
 *
 * Revision 1.7  2004/05/23 12:38:40  rjongbloed
 * Tidied up the output format of the codec listing
 *
 * Revision 1.6  2004/05/18 22:29:17  csoutheren
 * Added trace commands
 *
 * Revision 1.5  2004/05/18 07:08:42  csoutheren
 * Fixed problem with help being displayed in wrong places
 *
 * Revision 1.4  2004/05/18 00:05:15  rjongbloed
 * Fixed Win32 compatibility
 *
 * Revision 1.3  2004/05/12 13:42:16  csoutheren
 * Added more functions
 *
 * Revision 1.2  2004/05/11 14:07:34  csoutheren
 * Updated to display all plugin codec information
 *
 * Revision 1.1  2004/05/11 01:19:37  csoutheren
 * Initial version
 *
 */

#include <ptlib.h>

#ifdef __GNUC__
#define H323_STATIC_LIB
#endif


#include <h323.h>

class CodecInfo : public PProcess
{
  PCLASSINFO(CodecInfo, PProcess)

  public:
    CodecInfo();

    void Main();
};

#define new PNEW

PCREATE_PROCESS(CodecInfo)

///////////////////////////////////////////////////////////////

CodecInfo::CodecInfo()
  : PProcess("Post Increment", "CodecInfo")
{
}
PString DisplayLicenseType(int type)
{
  PString str;
  switch (type) {
    case PluginCodec_Licence_None:
      str = "No license";
      break;
    case PluginCodec_License_GPL:
      str = "GPL";
      break;
    case PluginCodec_License_MPL:
      str = "MPL";
      break;
    case PluginCodec_License_Freeware:
      str = "Freeware";
      break;
    case PluginCodec_License_ResearchAndDevelopmentUseOnly:
      str = "Research and development use only";
      break;
    case PluginCodec_License_BSD:
      str = "BSD";
      break;
    default:
      if (type <= PluginCodec_License_NoRoyalties)
        str = "No royalty license";
      else
        str = "Requires royalties";
      break;
  }
  return str;
}

PString DisplayableString(const char * str)
{
  if (str == NULL)
    return PString("(none)");
  return PString(str);
}

PString DisplayLicenseInfo(PluginCodec_information * info)
{
  PStringStream str;
  if (info == NULL) 
    str << "    None" << endl;
  else {
    str << "  License" << endl
        << "    Timestamp: " << PTime().AsString(PTime::RFC1123) << endl
        << "    Source" << endl
        << "      Author:       " << DisplayableString(info->sourceAuthor) << endl
        << "      Version:      " << DisplayableString(info->sourceVersion) << endl
        << "      Email:        " << DisplayableString(info->sourceEmail) << endl
        << "      URL:          " << DisplayableString(info->sourceURL) << endl
        << "      Copyright:    " << DisplayableString(info->sourceCopyright) << endl
        << "      License:      " << DisplayableString(info->sourceLicense) << endl
        << "      License Type: " << DisplayLicenseType(info->sourceLicenseCode) << endl
        << "    Codec" << endl
        << "      Description:  " << DisplayableString(info->codecDescription) << endl
        << "      Author:       " << DisplayableString(info->codecAuthor) << endl
        << "      Version:      " << DisplayableString(info->codecVersion) << endl
        << "      Email:        " << DisplayableString(info->codecEmail) << endl
        << "      URL:          " << DisplayableString(info->codecURL) << endl
        << "      Copyright:    " << DisplayableString(info->codecCopyright) << endl
        << "      License:      " << DisplayableString(info->codecLicense) << endl
        << "      License Type: " << DisplayLicenseType(info->codecLicenseCode) << endl;
  }
  return str;
}

void DisplayCodecDefn(PluginCodec_Definition & defn)
{
  cout << "  Version:             " << defn.version << endl
       << DisplayLicenseInfo(defn.info)
       << "  Flags:               ";
  switch (defn.flags & PluginCodec_MediaTypeMask) {
    case PluginCodec_MediaTypeAudio:
      cout << "Audio";
      break;
    case PluginCodec_MediaTypeVideo:
      cout << "Video";
      break;
    case PluginCodec_MediaTypeAudioStreamed:
      cout << "Streamed audio (" << ((defn.flags & PluginCodec_BitsPerSampleMask) >> PluginCodec_BitsPerSamplePos) << " bits per sample)";
      break;
    default:
      cout << "unknown type " << (defn.flags & PluginCodec_MediaTypeMask) << endl;
      break;
  }
  cout << ", " << ((defn.flags & PluginCodec_InputTypeRTP) ? "RTP input" : "raw input");
  cout << ", " << ((defn.flags & PluginCodec_OutputTypeRTP) ? "RTP output" : "raw output");
  cout << ", " << ((defn.flags & PluginCodec_RTPTypeExplicit) ? "explicit" : "dynamic") << " RTP payload";
  cout << endl;

  cout << "  Description:         " << defn.descr << endl
       << "  Source format:       " << defn.sourceFormat << endl
       << "  Dest format:         " << defn.destFormat << endl
       << "  Userdata:            " << (void *)defn.userData << endl
       << "  Sample rate:         " << defn.sampleRate << endl
       << "  Bits/sec:            " << defn.bitsPerSec << endl
       << "  Ns/frame:            " << defn.nsPerFrame << endl
       << "  Samples/frame:       " << defn.samplesPerFrame << endl
       << "  Bytes/frame:         " << defn.bytesPerFrame << endl
       << "  Frames/packet:       " << defn.recommendedFramesPerPacket << endl
       << "  Frames/packet (max): " << defn.maxFramesPerPacket << endl
       << "  RTP payload:         ";

  if (defn.flags & PluginCodec_RTPTypeExplicit)
    cout << (int)defn.rtpPayload << endl;
  else
    cout << "(not used)";

  cout << endl
       << "  SDP format:          " << DisplayableString(defn.sdpFormat) << endl;

  cout << "  Create function:     " << (void *)defn.createCodec << endl
       << "  Destroy function:    " << (void *)defn.destroyCodec << endl
       << "  Encode function:     " << (void *)defn.codecFunction << endl;

  cout << "  Codec controls:      ";
  if (defn.codecControls == NULL)
    cout << "(none)" << endl;
  else {
    cout << endl;
    PluginCodec_ControlDefn * ctls = defn.codecControls;
    while (ctls->name != NULL) {
      cout << "    " << ctls->name << "(" << (void *)ctls->control << ")" << endl;
      ++ctls;
    }
  }

  static char * capabilityNames[] = {
    "not defined",
    "programmed",
    "nonStandard",
    "generic",

    // audio codecs
    "G.711 Alaw 64k",
    "G.711 Alaw 56k",
    "G.711 Ulaw 64k",
    "G.711 Ulaw 56k",
    "G.722 64k",
    "G.722 56k",
    "G.722 48k",
    "G.723.1",
    "G.728",
    "G.729",
    "G.729 Annex A",
    "is11172",
    "is13818 Audio",
    "G.729 Annex B",
    "G.729 Annex A and Annex B",
    "G.723.1 Annex C",
    "GSM Full Rate",
    "GSM Half Rate",
    "GSM Enhanced Full Rate",
    "G.729 Extensions",

    // video codecs
    "H.261",
    "H.262",
    "H.263",
    "is11172"
  };

  cout << "  Capability type:     ";
  if (defn.h323CapabilityType < (sizeof(capabilityNames) / sizeof(capabilityNames[0])))
    cout << capabilityNames[defn.h323CapabilityType];
  else
    cout << "Unknown capability code " << defn.h323CapabilityType;

  switch (defn.h323CapabilityType) {
    case PluginCodec_H323Codec_undefined:
      break;

    case PluginCodec_H323Codec_nonStandard:
      if (defn.h323CapabilityData == NULL)
        cout << ", no data" << endl;
      else {
        struct PluginCodec_H323NonStandardCodecData * data =
            (struct PluginCodec_H323NonStandardCodecData *)defn.h323CapabilityData;
        if (data->objectId != NULL) 
          cout << ", objectID=" << data->objectId;
        else
          cout << ", t35=" << (int)data->t35CountryCode << "," << (int)data->t35Extension << "," << (int)data->manufacturerCode;
        if ((data->data == NULL) || (data->dataLength == 0))
          cout << ", empty data";
        else {
          BOOL printable = TRUE;
          for (unsigned i = 0; i < data->dataLength; ++i) 
            printable = printable && (0x20 <= data->data[i] && data->data[i] < 0x7e);
          if (printable)
            cout << ", data=" << PString((const char *)data->data, data->dataLength);
          else
            cout << ", " << (int)data->dataLength << " bytes";
        }
        if (data->capabilityMatchFunction != NULL) 
          cout << ", match function provided";
        cout << endl;
      }
      break;

    case PluginCodec_H323Codec_programmed:
    case PluginCodec_H323Codec_generic:
    case PluginCodec_H323AudioCodec_g711Alaw_64k:
    case PluginCodec_H323AudioCodec_g711Alaw_56k:
    case PluginCodec_H323AudioCodec_g711Ulaw_64k:
    case PluginCodec_H323AudioCodec_g711Ulaw_56k:
    case PluginCodec_H323AudioCodec_g722_64k:
    case PluginCodec_H323AudioCodec_g722_56k:
    case PluginCodec_H323AudioCodec_g722_48k:
    case PluginCodec_H323AudioCodec_g728:
    case PluginCodec_H323AudioCodec_g729:
    case PluginCodec_H323AudioCodec_g729AnnexA:
    case PluginCodec_H323AudioCodec_g729wAnnexB:
    case PluginCodec_H323AudioCodec_g729AnnexAwAnnexB:
      if (defn.h323CapabilityData != NULL)
        cout << (void *)defn.h323CapabilityData << endl;
      break;

    case PluginCodec_H323AudioCodec_g7231:
      cout << "silence supression " << ((defn.h323CapabilityData > 0) ? "on" : "off") << endl;
      break;

    case PluginCodec_H323AudioCodec_is11172:
    case PluginCodec_H323AudioCodec_is13818Audio:
    case PluginCodec_H323AudioCodec_g729Extensions:
      cout << "ignored";
      break;

    case PluginCodec_H323AudioCodec_g7231AnnexC:
      if (defn.h323CapabilityData == NULL)
        cout << ", no data" << endl;
      else 
        cout << "not displayed" << endl;
      break;

    case PluginCodec_H323AudioCodec_gsmFullRate:
    case PluginCodec_H323AudioCodec_gsmHalfRate:
    case PluginCodec_H323AudioCodec_gsmEnhancedFullRate:
      if (defn.h323CapabilityData == NULL)
        cout << ", no data -> default comfortNoise=0, scrambled=0" << endl;
      else {
        struct PluginCodec_H323AudioGSMData * data =
            (struct PluginCodec_H323AudioGSMData *)defn.h323CapabilityData;
        cout << ", comfort noise=" << data->comfortNoise << ", scrambled=" << data->scrambled;
        cout << endl;
      }
      break;

    case PluginCodec_H323VideoCodec_h261:
    case PluginCodec_H323VideoCodec_h262:
    case PluginCodec_H323VideoCodec_h263:
    case PluginCodec_H323VideoCodec_is11172:
      if (defn.h323CapabilityData == NULL)
        cout << ", no data" << endl;
      else 
        cout << "not displayed" << endl;
      break;

    default:
      break;
  }
}

void DisplayMediaFormats(const OpalMediaFormat::List & mediaList)
{
  PINDEX i;
  PINDEX max_len = 0;
  for (i = 0; i < mediaList.GetSize(); i++) {
    PINDEX len = mediaList[i].GetLength();
    if (len > max_len)
      max_len = len;
  }

  for (i = 0; i < mediaList.GetSize(); i++) {
    OpalMediaFormat & fmt = mediaList[i];
    cout << setw(max_len+2) << fmt << "  ";
    switch (fmt.GetDefaultSessionID()) {
      case OpalMediaFormat::DefaultAudioSessionID:
        cout << "audio, rate=" << fmt.GetBandwidth() << ", RTP=" << fmt.GetPayloadType() << endl;
        break;
      case OpalMediaFormat::DefaultVideoSessionID:
        cout << "video, rate=" << fmt.GetBandwidth() << ", RTP=" << fmt.GetPayloadType() << endl;
        break;
      case OpalMediaFormat::DefaultDataSessionID:
        cout << "data" << endl;;
        break;
      default:
        cout << "unknown type " << mediaList[i].GetDefaultSessionID() << endl;
    }
  }
}

void CodecInfo::Main()
{
  cout << GetName()
       << " Version " << GetVersion(TRUE)
       << " by " << GetManufacturer()
       << " on " << GetOSClass() << ' ' << GetOSName()
       << " (" << GetOSVersion() << '-' << GetOSHardware() << ")\n\n";

  // Get and parse all of the command line arguments.
  PArgList & args = GetArguments();
  args.Parse(
             "t-trace."
             "o-output:"
             "c-codecs."
             "h-help."
             "i-info:"
             "m-mediaformats."
             "p-pluginlist."
             "a-capabilities:"
             "C-caps:"
             "f-factory"
             , FALSE);


  PTrace::Initialise(args.GetOptionCount('t'),
                     args.HasOption('o') ? (const char *)args.GetOptionString('o') : NULL,
         PTrace::Blocks | PTrace::Timestamp | PTrace::Thread | PTrace::FileAndLine);

  OpalMediaFormat::List mediaList = OpalMediaFormat::GetRegisteredMediaFormats();
  H323PluginCodecManager & codecMgr = *(H323PluginCodecManager *)PFactory<PPluginModuleManager>::CreateInstance("H323PluginCodecManager");
  PPluginModuleManager::PluginListType pluginList = codecMgr.GetPluginList();
  OpalMediaFormat::List stdCodecList = H323PluginCodecManager::GetMediaFormats();
  H323CapabilityFactory::KeyList_T keyList = H323CapabilityFactory::GetKeyList();

  if (args.HasOption('a')) {
    cout << "Registered capabilities:" << endl
         << setfill(',') << PStringArray(keyList) << setfill(' ')
         << endl;
    return;
  }

  if (args.HasOption('C')) {
    PString spec = args.GetOptionString('C');
    H323Capabilities caps;
    caps.AddAllCapabilities(0, 0, spec);
    cout << "Standard capability set:" << caps << endl;
    for (PINDEX i = 0; i < stdCodecList.GetSize(); i++) {
      PString fmt = stdCodecList[i];
      caps.FindCapability(fmt);
    }
    return;
  }


  if (args.HasOption('c')) {
    cout << "Standard codecs:" << endl;
    DisplayMediaFormats(stdCodecList);
    return;
  }

  if (args.HasOption('m')) {
    cout << "Registered media formats:" << endl;
    DisplayMediaFormats(mediaList);
    return;
  }

  if (args.HasOption('p')) {
    cout << "Plugin codecs:" << endl;
    for (int i = 0; i < pluginList.GetSize(); i++) {
      cout << "   " << pluginList.GetKeyAt(i) << endl;
    }
    return;
  }

  if (args.HasOption('i')) {
    PString name = args.GetOptionString('i');
    if (name.IsEmpty()) {
      cout << "error: -i must specify name of plugin" << endl;
      return;
    }
    for (int i = 0; i < pluginList.GetSize(); i++) {
      if (pluginList.GetKeyAt(i) == name) {
        PDynaLink & dll = pluginList.GetDataAt(i);
        PluginCodec_GetCodecFunction getCodecs;
        if (!dll.GetFunction(PLUGIN_CODEC_GET_CODEC_FN_STR, (PDynaLink::Function &)getCodecs)) {
          cout << "error: " << name << " is missing the function " << PLUGIN_CODEC_GET_CODEC_FN_STR << endl;
          return;
        }
        unsigned int count;
        PluginCodec_Definition * codecs = (*getCodecs)(&count, PLUGIN_CODEC_VERSION);
        if (codecs == NULL || count == 0) {
          cout << "error: " << name << " does not define any codecs for this version of the plugin API" << endl;
          return;
        } 
        cout << name << " contains " << count << " coders:" << endl;
        for (unsigned j = 0; j < count; j++) {
          cout << "---------------------------------------" << endl
               << "Coder " << j+1 << endl;
          DisplayCodecDefn(codecs[j]);
        }
        return;
      }
    }
    cout << "error: plugin \"" << name << "\" not found" << endl;
    return;
  }

  if (args.HasOption('f')) {
    PFactory<OpalFactoryCodec>::KeyList_T list = PFactory<OpalFactoryCodec>::GetKeyList();
    cout << "Codec factories:" << endl;
    for (PFactory<OpalFactoryCodec>::KeyList_T::const_iterator r = list.begin(); r != list.end(); ++r)
      cout << *r << endl;
    PFactory<OpalFactoryCodec>::CreateInstance("G.711-uLaw-64k|L16");
    return;
  }

  cout << "available options:" << endl
       << "  -c --codecs         display standard codecs\n"
       << "  -h --help           display this help message\n"
       << "  -i --info name      display info about a plugin\n"
       << "  -m --mediaformats   display media formats\n"
       << "  -p --pluginlist     display codec plugins\n"
       << "  -C --caps spec      display capabilities that match the specification\n"
       << "  -f --factory        display codec conversion factories\n"
  ;
}
