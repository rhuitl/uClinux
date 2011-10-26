/*
 * main.cxx
 *
 * A simple H.323 "net telephone" application.
 *
 * Copyright (c) 2000 Equivalence Pty. Ltd.
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
 * The Original Code is Portable Windows Library.
 *
 * The Initial Developer of the Original Code is Equivalence Pty. Ltd.
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: main.cxx,v $
 * Revision 1.33  2004/12/20 02:33:58  csoutheren
 * Updated for changes to function names
 *
 * Revision 1.32  2004/12/16 00:46:02  csoutheren
 * Added osptoken option
 *
 * Revision 1.31  2004/12/16 00:30:19  csoutheren
 * Added osptoken option
 *
 * Revision 1.30  2004/12/09 23:42:08  csoutheren
 * Added support for outgoing OSP-routed calls
 *
 * Revision 1.29  2004/12/08 02:22:46  csoutheren
 * Added support for outgoing OSP-routed calls
 *
 * Revision 1.28  2004/09/08 00:54:14  csoutheren
 * Added ability to send user indication messages
 *
 * Revision 1.27  2004/05/20 02:07:29  csoutheren
 * Use macro to work around MSVC internal compiler errors
 *
 * Revision 1.26  2002/11/13 10:13:16  rogerh
 * Add Speex codec.
 *
 * Revision 1.25  2002/11/10 08:10:43  robertj
 * Moved constants for "well known" ports to better place (OPAL change).
 *
 * Revision 1.24  2002/11/10 04:26:55  robertj
 * Fixed setting of jitter paramters
 *
 * Revision 1.23  2002/11/04 10:27:48  rogerh
 * Only print duration when a connection was made. (copied from ohphone)
 *
 * Revision 1.22  2002/10/31 00:52:18  robertj
 * Enhanced jitter buffer system so operates dynamically between minimum and
 *   maximum values. Altered API to assure app writers note the change!
 *
 * Revision 1.21  2002/07/17 05:52:21  robertj
 * Fixed using -i parameter for interface when discovering gk, thanks Steve Frare
 *
 * Revision 1.20  2002/02/11 06:20:07  robertj
 * Moved version.h to root directory so have one for the library and not just
 *   the sample application. SimpH323 uses the library version so they remain
 *   in sync.
 *
 * Revision 1.19  2001/11/01 01:35:25  robertj
 * Added default Fast Start disabled and H.245 tunneling disable flags
 *   to the endpoint instance.
 *
 * Revision 1.18  2001/10/24 01:20:34  robertj
 * Added code to help with static linking of H323Capability names database.
 *
 * Revision 1.17  2001/09/27 23:58:31  robertj
 * Fixed incorrect character in parameter decode, thanks Carlo Kielstra
 *
 * Revision 1.16  2001/08/24 13:34:40  rogerh
 * Delete the listener if StartListener() failed.
 *
 * Revision 1.15  2001/08/10 10:06:50  robertj
 * No longer need SSL to have H.235 security.
 *
 * Revision 1.14  2001/08/06 03:18:35  robertj
 * Fission of h323.h to h323ep.h & h323con.h, h323.h now just includes files.
 * Improved access to H.235 secure RAS functionality.
 * Changes to H.323 secure RAS contexts to help use with gk server.
 *
 * Revision 1.13  2001/08/03 11:56:26  robertj
 * Added conditional compile for H.235 stuff.
 *
 * Revision 1.12  2001/07/13 08:44:16  robertj
 * Fixed incorrect inclusion of hardware codec capabilities.
 *
 * Revision 1.11  2001/05/17 07:11:29  robertj
 * Added more call end types for common transport failure modes.
 *
 * Revision 1.10  2001/05/14 05:56:26  robertj
 * Added H323 capability registration system so can add capabilities by
 *   string name instead of having to instantiate explicit classes.
 *
 * Revision 1.9  2001/03/21 04:52:40  robertj
 * Added H.235 security to gatekeepers, thanks Fürbass Franz!
 *
 * Revision 1.8  2001/03/20 23:42:55  robertj
 * Used the new PTrace::Initialise function for starting trace code.
 *
 * Revision 1.7  2000/10/16 08:49:31  robertj
 * Added single function to add all UserInput capability types.
 *
 * Revision 1.6  2000/07/31 14:08:09  robertj
 * Added fast start and H.245 tunneling flags to the H323Connection constructor so can
 *    disabled these features in easier manner to overriding virtuals.
 *
 * Revision 1.5  2000/06/20 02:38:27  robertj
 * Changed H323TransportAddress to default to IP.
 *
 * Revision 1.4  2000/06/07 05:47:55  robertj
 * Added call forwarding.
 *
 * Revision 1.3  2000/05/23 11:32:27  robertj
 * Rewrite of capability table to combine 2 structures into one and move functionality into that class
 *    allowing some normalisation of usage across several applications.
 * Changed H323Connection so gets a copy of capabilities instead of using endponts, allows adjustments
 *    to be done depending on the remote client application.
 *
 * Revision 1.2  2000/05/11 10:00:02  robertj
 * Fixed setting and resetting of current call token variable.
 *
 * Revision 1.1  2000/05/11 04:05:57  robertj
 * Simple sample program.
 *
 */

#include <ptlib.h>

#ifdef __GNUC__
#define H323_STATIC_LIB
#endif

#include "main.h"
#include "../../version.h"


#define new PNEW

PCREATE_PROCESS(SimpleH323Process);


///////////////////////////////////////////////////////////////

SimpleH323Process::SimpleH323Process()
  : PProcess("OpenH323 Project", "SimpleH323",
             MAJOR_VERSION, MINOR_VERSION, BUILD_TYPE, BUILD_NUMBER)
{
  endpoint = NULL;
}


SimpleH323Process::~SimpleH323Process()
{
  delete endpoint;
}


void SimpleH323Process::Main()
{
  cout << GetName()
       << " Version " << GetVersion(TRUE)
       << " by " << GetManufacturer()
       << " on " << GetOSClass() << ' ' << GetOSName()
       << " (" << GetOSVersion() << '-' << GetOSHardware() << ")\n\n";

  // Get and parse all of the command line arguments.
  PArgList & args = GetArguments();
  args.Parse(
             "a-auto-answer."
             "b-bandwidth:"
             "B-forward-busy:"
             "D-disable:"
             "e-silence."
             "f-fast-disable."
             "g-gatekeeper:"
             "h-help."
             "i-interface:"
             "j-jitter:"
             "l-listen."
             "n-no-gatekeeper."
#if PTRACING
             "o-output:"
#endif
#ifdef H323_TRANSNEXUS_OSP
             "-osp:"
             "-ospdir:"
#endif
             "-osptoken."
             "P-prefer:"
             "p-password:"
             "r-require-gatekeeper."
             "s-sound:"
             "-sound-in:"
             "-sound-out:"
             "T-h245tunneldisable."
#if PTRACING
             "t-trace."
#endif
             "u-user:"
          , FALSE);


  if (args.HasOption('h') || (!args.HasOption('l') && args.GetCount() == 0)) {
    cout << "Usage : " << GetName() << " [options] -l\n"
            "      : " << GetName() << " [options] [alias@]hostname   (no gatekeeper)\n"
            "      : " << GetName() << " [options] alias[@hostname]   (with gatekeeper)\n"
            "Options:\n"
            "  -l --listen             : Listen for incoming calls.\n"
            "  -g --gatekeeper host    : Specify gatekeeper host.\n"
            "  -n --no-gatekeeper      : Disable gatekeeper discovery.\n"
            "  -r --require-gatekeeper : Exit if gatekeeper discovery fails.\n"
            "  -a --auto-answer        : Automatically answer incoming calls.\n"
            "  -u --user name          : Set local alias name(s) (defaults to login name).\n"
            "  -p --password pwd       : Set the H.235 password to use for calls.\n"
            "  -b --bandwidth bps      : Limit bandwidth usage to bps bits/second.\n"
            "  -j --jitter [min-]max   : Set minimum (optional) and maximum jitter buffer (in milliseconds).\n"
            "  -D --disable codec      : Disable the specified codec (may be used multiple times)\n"
            "  -P --prefer codec       : Prefer the specified codec (may be used multiple times)\n"
            "  -i --interface ipnum    : Select interface to bind to.\n"
            "  -B --forward-busy party : Forward to remote party if busy.\n"
            "  -e --silence            : Disable transmitter silence detection.\n"
            "  -f --fast-disable       : Disable fast start.\n"
            "  -T --h245tunneldisable  : Disable H245 tunnelling.\n"
            "  -s --sound device       : Select sound input/output device.\n"
            "     --sound-in device    : Select sound input device.\n"
            "     --sound-out device   : Select sound output device.\n"
#ifdef H323_TRANSNEXUS_OSP
            "  --osp server            : Use OSP server for number resolution (disable GK if selected).\n"
            "  --ospdir dir            : Directory in which OSP certs are stored\n"
#endif
            "  --osptoken              : Copy OSP tokens (if present) from ACF to SETUP\n"
#if PTRACING 
            "  -t --trace              : Enable trace, use multiple times for more detail.\n"
            "  -o --output             : File for trace output, default is stderr.\n"
#endif
            "  -h --help               : This help message.\n"
            << endl;
    return;
  }

#if PTRACING
  PTrace::Initialise(args.GetOptionCount('t'),
                     args.HasOption('o') ? (const char *)args.GetOptionString('o') : NULL);
#endif

  // Create the H.323 endpoint and initialise it
  endpoint = new SimpleH323EndPoint;
  if (!endpoint->Initialise(args))
    return;

  // See if making a call or just listening.
  if (args.HasOption('l'))
    cout << "Waiting for incoming calls for \"" << endpoint->GetLocalUserName() << "\"\n";
  else {
    cout << "Initiating call to \"" << args[0] << "\"\n";
    endpoint->MakeCall(args[0], endpoint->currentCallToken);
  }
  cout << "Press X to exit." << endl;

  // Simplest possible user interface
  for (;;) {
    cout << "H323> " << flush;
    PCaselessString cmd;
    cin >> cmd;
    if (cmd == "X")
      break;

    if (cmd.FindOneOf("HYN0123456789ABCD") != P_MAX_INDEX) {
      H323Connection * connection = endpoint->FindConnectionWithLock(endpoint->currentCallToken);
      if (connection != NULL) {
        if (cmd == "H")
          connection->ClearCall();
        else if (cmd == "Y")
          connection->AnsweringCall(H323Connection::AnswerCallNow);
        else if (cmd == "N")
          connection->AnsweringCall(H323Connection::AnswerCallDenied);
        else
          connection->SendUserInput(cmd);
        connection->Unlock();
      }
    }
  }

  cout << "Exiting " << GetName() << endl;
}


///////////////////////////////////////////////////////////////

SimpleH323EndPoint::SimpleH323EndPoint()
{
}


SimpleH323EndPoint::~SimpleH323EndPoint()
{
}


BOOL SimpleH323EndPoint::Initialise(PArgList & args)
{
  // Get local username, multiple uses of -u indicates additional aliases
  if (args.HasOption('u')) {
    PStringArray aliases = args.GetOptionString('u').Lines();
    SetLocalUserName(aliases[0]);
    for (PINDEX i = 1; i < aliases.GetSize(); i++)
      AddAliasName(aliases[i]);
  }

  // Set the various options
  SetSilenceDetectionMode(args.HasOption('e') ? H323AudioCodec::NoSilenceDetection
                                              : H323AudioCodec::AdaptiveSilenceDetection);
  DisableFastStart(args.HasOption('f'));
  DisableH245Tunneling(args.HasOption('T'));

  autoAnswer           = args.HasOption('a');
  busyForwardParty     = args.GetOptionString('B');

  if (args.HasOption('b')) {
    initialBandwidth = args.GetOptionString('b').AsUnsigned()*100;
    if (initialBandwidth == 0) {
      cerr << "Illegal bandwidth specified." << endl;
      return FALSE;
    }
  }

  if (args.HasOption('j')) {
    unsigned minJitter;
    unsigned maxJitter;
    PStringArray delays = args.GetOptionString('j').Tokenise(",-");
    if (delays.GetSize() < 2) {
      maxJitter = delays[0].AsUnsigned();
      minJitter = PMIN(GetMinAudioJitterDelay(), maxJitter);
    }
    else {
      minJitter = delays[0].AsUnsigned();
      maxJitter = delays[1].AsUnsigned();
    }
    if (minJitter >= 20 && minJitter <= maxJitter && maxJitter <= 1000)
      SetAudioJitterDelay(minJitter, maxJitter);
    else {
      cerr << "Jitter should be between 20 and 1000 milliseconds." << endl;
      return FALSE;
    }
  }

  if (!SetSoundDevice(args, "sound", PSoundChannel::Recorder))
    return FALSE;
  if (!SetSoundDevice(args, "sound", PSoundChannel::Player))
    return FALSE;
  if (!SetSoundDevice(args, "sound-in", PSoundChannel::Recorder))
    return FALSE;
  if (!SetSoundDevice(args, "sound-out", PSoundChannel::Player))
    return FALSE;


  // Set the default codecs available on sound cards.
  AddAllCapabilities(0, 0, "*");
  AddAllUserInputCapabilities(0, 1);

  RemoveCapabilities(args.GetOptionString('D').Lines());
  ReorderCapabilities(args.GetOptionString('P').Lines());

  cout << "Local username: " << GetLocalUserName() << "\n"
    << "Silence compression is " << (GetSilenceDetectionMode() == H323AudioCodec::NoSilenceDetection ? "Dis" : "En") << "abled\n"
       << "Auto answer is " << autoAnswer << "\n"
       << "FastConnect is " << (IsFastStartDisabled() ? "Dis" : "En") << "abled\n"
       << "H245Tunnelling is " << (IsH245TunnelingDisabled() ? "Dis" : "En") << "abled\n"
       << "Jitter buffer: "  << GetMinAudioJitterDelay() << '-' << GetMaxAudioJitterDelay() << " ms\n"
       << "Sound output device: \"" << GetSoundChannelPlayDevice() << "\"\n"
          "Sound  input device: \"" << GetSoundChannelRecordDevice() << "\"\n"
       <<  "Codecs (in preference order):\n" << setprecision(2) << GetCapabilities() << endl;


  // Start the listener thread for incoming calls.
  H323TransportAddress iface = args.GetOptionString('i');
  if (iface.IsEmpty())
    iface = "*";
  if (!StartListener(iface)) {
    cerr <<  "Could not open H.323 listener port on \"" << iface << '"' << endl;
    return FALSE;
  }


  // Initialise the security info
  if (args.HasOption('p')) {
    SetGatekeeperPassword(args.GetOptionString('p'));
    cout << "Enabling H.235 security access to gatekeeper." << endl;
  }

#ifdef H323_TRANSNEXUS_OSP
  if (args.HasOption("osp")) {
    PDirectory ospDir;
    if (args.HasOption("ospdir"))
      ospDir = args.GetOptionString("ospdir");
    SetOSPProvider(args.GetOptionString("osp"));
  }
  else
#endif

  // Establish link with gatekeeper if required.
  if (args.HasOption('g') || !args.HasOption('n')) {
    H323TransportUDP * rasChannel;
    if (args.GetOptionString('i').IsEmpty())
      rasChannel  = new H323TransportUDP(*this);
    else {
      PIPSocket::Address interfaceAddress(args.GetOptionString('i'));
      rasChannel  = new H323TransportUDP(*this, interfaceAddress);
    }

    if (args.HasOption('g')) {
      PString gkName = args.GetOptionString('g');
      if (SetGatekeeper(gkName, rasChannel))
        cout << "Gatekeeper set: " << *gatekeeper << endl;
      else {
        cerr << "Error registering with gatekeeper at \"" << gkName << '"' << endl;
        return FALSE;
      }
    }
    else {
      cout << "Searching for gatekeeper..." << flush;
      if (DiscoverGatekeeper(rasChannel))
        cout << "\nGatekeeper found: " << *gatekeeper << endl;
      else {
        cerr << "\nNo gatekeeper found." << endl;
        if (args.HasOption('r')) 
          return FALSE;
      }
    }
  }

  // osptoken option only makes sense if gatekeeper is being used
  if ((gatekeeper != NULL) && args.HasOption("osptoken"))
    SetGkAccessTokenOID(OpalOSP::ETSIXMLTokenOID);

  return TRUE;
}


BOOL SimpleH323EndPoint::SetSoundDevice(PArgList & args,
                                        const char * optionName,
                                        PSoundChannel::Directions dir)
{
  if (!args.HasOption(optionName))
    return TRUE;

  PString dev = args.GetOptionString(optionName);

  if (dir == PSoundChannel::Player) {
    if (SetSoundChannelPlayDevice(dev))
      return TRUE;
  }
  else {
    if (SetSoundChannelRecordDevice(dev))
      return TRUE;
  }

  cerr << "Device for " << optionName << " (\"" << dev << "\") must be one of:\n";

  PStringArray names = PSoundChannel::GetDeviceNames(dir);
  for (PINDEX i = 0; i < names.GetSize(); i++)
    cerr << "  \"" << names[i] << "\"\n";

  return FALSE;
}


H323Connection * SimpleH323EndPoint::CreateConnection(unsigned callReference)
{
  return new SimpleH323Connection(*this, callReference);
}


BOOL SimpleH323EndPoint::OnIncomingCall(H323Connection & connection,
                                        const H323SignalPDU &,
                                        H323SignalPDU &)
{
  if (currentCallToken.IsEmpty())
    return TRUE;

  if (busyForwardParty.IsEmpty()) {
    cout << "Incoming call from \"" << connection.GetRemotePartyName() << "\" rejected, line busy!" << endl;
    return FALSE;
  }

  cout << "Forwarding call to \"" << busyForwardParty << "\"." << endl;
  return !connection.ForwardCall(busyForwardParty);
}


H323Connection::AnswerCallResponse
                   SimpleH323EndPoint::OnAnswerCall(H323Connection & connection,
                                                    const PString & caller,
                                                    const H323SignalPDU &,
                                                    H323SignalPDU &)
{
  currentCallToken = connection.GetCallToken();

  if (autoAnswer) {
    cout << "Automatically accepting call." << endl;
    return H323Connection::AnswerCallNow;
  }

  cout << "Incoming call from \""
       << caller
       << "\", answer call (Y/n)? "
       << flush;

  return H323Connection::AnswerCallPending;
}


BOOL SimpleH323EndPoint::OnConnectionForwarded(H323Connection & /*connection*/,
                                               const PString & forwardParty,
                                               const H323SignalPDU & /*pdu*/)
{
  if (MakeCall(forwardParty, currentCallToken)) {
    cout << "Call is being forwarded to host " << forwardParty << endl;
    return TRUE;
  }

  cout << "Error forwarding call to \"" << forwardParty << '"' << endl;
  return FALSE;
}


void SimpleH323EndPoint::OnConnectionEstablished(H323Connection & connection,
                                                 const PString & token)
{
  currentCallToken = token;
  cout << "In call with " << connection.GetRemotePartyName() << endl;
}


void SimpleH323EndPoint::OnConnectionCleared(H323Connection & connection,
                                             const PString & clearedCallToken)
{
  if (currentCallToken == clearedCallToken)
    currentCallToken = PString();

  PString remoteName = '"' + connection.GetRemotePartyName() + '"';
  switch (connection.GetCallEndReason()) {
    case H323Connection::EndedByRemoteUser :
      cout << remoteName << " has cleared the call";
      break;
    case H323Connection::EndedByCallerAbort :
      cout << remoteName << " has stopped calling";
      break;
    case H323Connection::EndedByRefusal :
      cout << remoteName << " did not accept your call";
      break;
    case H323Connection::EndedByNoAnswer :
      cout << remoteName << " did not answer your call";
      break;
    case H323Connection::EndedByTransportFail :
      cout << "Call with " << remoteName << " ended abnormally";
      break;
    case H323Connection::EndedByCapabilityExchange :
      cout << "Could not find common codec with " << remoteName;
      break;
    case H323Connection::EndedByNoAccept :
      cout << "Did not accept incoming call from " << remoteName;
      break;
    case H323Connection::EndedByAnswerDenied :
      cout << "Refused incoming call from " << remoteName;
      break;
    case H323Connection::EndedByNoUser :
      cout << "Gatekeeper could find user " << remoteName;
      break;
    case H323Connection::EndedByNoBandwidth :
      cout << "Call to " << remoteName << " aborted, insufficient bandwidth.";
      break;
    case H323Connection::EndedByUnreachable :
      cout << remoteName << " could not be reached.";
      break;
    case H323Connection::EndedByHostOffline :
      cout << remoteName << " is not online.";
      break;
    case H323Connection::EndedByNoEndPoint :
      cout << "No phone running for " << remoteName;
      break;
    case H323Connection::EndedByConnectFail :
      cout << "Transport error calling " << remoteName;
      break;
    default :
      cout << "Call with " << remoteName << " completed";
  }
  PTime connectTime = connection.GetConnectionStartTime();
  if (connectTime.GetTimeInSeconds() != 0)
    cout << ", duration "
         << setprecision(0) << setw(5)
         << (PTime() - connectTime);

  cout << endl;
}


BOOL SimpleH323EndPoint::OpenAudioChannel(H323Connection & connection,
                                          BOOL isEncoding,
                                          unsigned bufferSize,
                                          H323AudioCodec & codec)
{
  if (H323EndPoint::OpenAudioChannel(connection, isEncoding, bufferSize, codec))
    return TRUE;

  cerr << "Could not open sound device ";
  if (isEncoding)
    cerr << GetSoundChannelRecordDevice();
  else
    cerr << GetSoundChannelPlayDevice();
  cerr << " - Check permissions or full duplex capability." << endl;

  return FALSE;
}



///////////////////////////////////////////////////////////////

SimpleH323Connection::SimpleH323Connection(SimpleH323EndPoint & ep, unsigned ref)
  : H323Connection(ep, ref)
{
}


BOOL SimpleH323Connection::OnStartLogicalChannel(H323Channel & channel)
{
  if (!H323Connection::OnStartLogicalChannel(channel))
    return FALSE;

  cout << "Started logical channel: ";

  switch (channel.GetDirection()) {
    case H323Channel::IsTransmitter :
      cout << "sending ";
      break;

    case H323Channel::IsReceiver :
      cout << "receiving ";
      break;

    default :
      break;
  }

  cout << channel.GetCapability() << endl;  

  return TRUE;
}



void SimpleH323Connection::OnUserInputString(const PString & value)
{
  cout << "User input received: \"" << value << '"' << endl;
}



// End of File ///////////////////////////////////////////////////////////////

