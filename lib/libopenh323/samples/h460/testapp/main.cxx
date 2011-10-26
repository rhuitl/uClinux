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
 * Revision 1.3  2006/05/16 18:49:58  shorne
 * Added more ReleaseComplete notifications
 *
 * Revision 1.2  2006/05/16 16:07:41  shorne
 * removed old revision information
 *
 * Revision 1.1  2006/05/16 16:03:38  shorne
 * Initial commit
 *
 *
 */

#include <ptlib.h>

#ifdef __GNUC__
#define H323_STATIC_LIB
#endif

#include "main.h"
#include "version.h"

#include <h323pdu.h>
#include <h460.h>

#define new PNEW

PCREATE_PROCESS(MyH323Process);


///////////////////////////////////////////////////////////////

MyH323Process::MyH323Process()
  : PProcess("OpenH323 Project", "MyH323",
             MAJOR_VERSION, MINOR_VERSION, BUILD_TYPE, BUILD_NUMBER)
{
  endpoint = NULL;
}


MyH323Process::~MyH323Process()
{
  delete endpoint;
}


void MyH323Process::Main()
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
  endpoint = new MyH323EndPoint;
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

 //   if (cmd.FindOneOf("HYN0123456789ABCD") != P_MAX_INDEX) {
      MyH323Connection * connection = (MyH323Connection *)endpoint->FindConnectionWithLock(endpoint->currentCallToken);
      if (connection != NULL) {
        if (cmd == "H")
          connection->ClearCall();
        else if (cmd == "Y")
          connection->AnsweringCall(H323Connection::AnswerCallNow);
        else if (cmd == "N")
          connection->AnsweringCall(H323Connection::AnswerCallDenied);
		else if (cmd == "T")
		   if (!connection->IMsession) 
              endpoint->IMOpenSession(endpoint->currentCallToken);
		   else
              endpoint->IMCloseSession(endpoint->currentCallToken);

        else if (connection->IMsession)
		   endpoint->SendIM(endpoint->currentCallToken, cmd);
		else
           connection->SendUserInput(cmd);
		 
        connection->Unlock();
      }
	  else if ((cmd.GetLength() > 1) && 
			     ((cmd.Left(1) == "c") || (cmd.Left(1) == "t"))) {

	        PStringArray Cmd = cmd.Tokenise("'",FALSE);

		  if (cmd.Left(1) == "t") {
			  endpoint->IMCall = TRUE;        // Is an IM Call
			  if (Cmd.GetSize() > 1)        
			    endpoint->IMmsg = Cmd[1];     // Message to send and disconnect
			  else 
                endpoint->IMsession = TRUE;   // Start an IM Session
		  }
			
			PString number = Cmd[0].Right(Cmd[0].GetLength()-2).Trim();
			endpoint->MakeCall(number,endpoint->currentCallToken);
      }
	  else 
		cout << "Oops something is wrong!" << endl;
//  }
  }

  cout << "Exiting " << GetName() << endl;
}


///////////////////////////////////////////////////////////////

MyH323EndPoint::MyH323EndPoint()
{

currentCallToken = PString();

IMsession = FALSE;
IMCall = FALSE;
IMmsg = PString();

}


MyH323EndPoint::~MyH323EndPoint()
{
}


BOOL MyH323EndPoint::Initialise(PArgList & args)
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

/////////////////////////////////////////
// List all the available Features
    PStringList features = H460_Feature::GetFeatureNames();
	  cout << "Available Features: " << endl;
      for (PINDEX i = 0; i < features.GetSize(); i++) {
	      PStringList names = H460_Feature::GetFeatureFriendlyNames(features[i]);
		    for (PINDEX j = 0; j < names.GetSize(); j++)
				cout << features[i] <<"     " << names[j] << endl;
	  }
	  cout << endl;
/////////////////////////////////////////

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


BOOL MyH323EndPoint::SetSoundDevice(PArgList & args,
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


H323Connection * MyH323EndPoint::CreateConnection(unsigned callReference)
{
  return new MyH323Connection(*this, callReference);
}


BOOL MyH323EndPoint::OnIncomingCall(H323Connection & connection,
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
                   MyH323EndPoint::OnAnswerCall(H323Connection & connection,
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


BOOL MyH323EndPoint::OnConnectionForwarded(H323Connection & /*connection*/,
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


void MyH323EndPoint::OnConnectionEstablished(H323Connection & connection,
                                                 const PString & token)
{
  currentCallToken = token;
  cout << "In call with " << connection.GetRemotePartyName() << endl;
}


void MyH323EndPoint::OnConnectionCleared(H323Connection & connection,
                                             const PString & clearedCallToken)
{

  currentCallToken = PString();

  if (((MyH323Connection &)connection).IMCall)
	  return;

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


BOOL MyH323EndPoint::OpenAudioChannel(H323Connection & connection,
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


BOOL MyH323EndPoint::OnSendFeatureSet(unsigned id, H225_FeatureSet & Message)
{
   return features.SendFeature(id, Message);
}

void MyH323EndPoint::OnReceiveFeatureSet(unsigned id, const H225_FeatureSet & Message)
{
   features.ReceiveFeature(id, Message);
}

static const char * IMOID = "1.3.6.1.4.1.17090.0.1";

BOOL MyH323EndPoint::OnSendCallIndependentSupplementaryService(const H323Connection * connection, 
														       H323SignalPDU & pdu)
{

  const Q931 & q931 = pdu.GetQ931();
  if (q931.GetMessageType() != Q931::SetupMsg) 
	    return FALSE;

  /// check to see if 
  MyH323Connection * con = (MyH323Connection *)connection;
  H460_FeatureSet * featset = con->GetFeatureSet();
  H460_FeatureID ID = H460_FeatureID(OpalOID(IMOID));

  if ((!IMCall) || (!featset->HasFeature(ID)))
	  return FALSE;

  MyH323Connection * conn = (MyH323Connection *)FindConnectionWithLock(con->GetCallToken()); 
  if (conn != NULL) {
	 conn->SetNonCallConnection();  // Set Flag to specify a Non Connection connection
     conn->IMCall = TRUE;           // Open Call  
	 conn->IMsession = IMsession;   // Flag to specify if a IM session
     conn->IMmsg = IMmsg;           // IM Message
	 currentCallToken = connection->GetCallToken();
	 IMCall = IMsession = FALSE;    // Reset flag
	 conn->Unlock();
  }

  H225_Setup_UUIE & setup = pdu.m_h323_uu_pdu.m_h323_message_body;
  setup.m_conferenceGoal.SetTag(H225_Setup_UUIE_conferenceGoal::e_callIndependentSupplementaryService);

  H225_FeatureSet fs;
  if (featset->SendFeature(H460_MessageType::e_setup, fs)) {
	if (fs.HasOptionalField(H225_FeatureSet::e_supportedFeatures)) {
        setup.IncludeOptionalField(H225_Setup_UUIE::e_supportedFeatures);
	    H225_ArrayOf_FeatureDescriptor & fsn = setup.m_supportedFeatures;
	    fsn = fs.m_supportedFeatures;
	}
	return TRUE;
  }

  return FALSE;

}

BOOL MyH323EndPoint::OnReceiveCallIndependentSupplementaryService(const H323Connection * connection, 
														          const H323SignalPDU & pdu)
{
 

  const Q931 & q931 = pdu.GetQ931();
  if (q931.GetMessageType() != Q931::SetupMsg) 
	    return FALSE;

  const H225_Setup_UUIE & setup = pdu.m_h323_uu_pdu.m_h323_message_body;
		if (!setup.HasOptionalField(H225_Setup_UUIE::e_supportedFeatures))
			   return FALSE;

  PTRACE(6,"MyEP\tReceived Call Independent Supplementary Service");

  currentCallToken = connection->GetCallToken();

  // Get the FeatureSet
  H460_FeatureSet * featset = ((MyH323Connection *)connection)->GetFeatureSet();

  H460_FeatureID ID = H460_FeatureID(OpalOID(IMOID));
  if (!featset->HasFeature(ID))
	  return FALSE;

  return TRUE;

}

void MyH323EndPoint::SupportsIM(const PString & token)
{

}

void MyH323EndPoint::ReceivedIM(const PString & token, const PString & msg)
{
  MyH323Connection * connection = (MyH323Connection *)FindConnectionWithLock(token);

  if (connection != NULL) {
	 cout << "Message Received from " 
	 << connection->GetRemotePartyName() << endl;	 
	 connection->Unlock();
  }
	 cout << "     " << msg << endl;
}

void MyH323EndPoint::SendIM(const PString & token, const PString & msg)
{

  MyH323Connection * connection = (MyH323Connection *)FindConnectionWithLock(token);

  if (connection != NULL) {
	  if (!connection->IMsession)
         connection->IMsession = TRUE;

	   connection->IMmsg = msg;
       H323SignalPDU facilityPDU;
       facilityPDU.BuildFacility(*connection, FALSE);
	   connection->WriteSignalPDU(facilityPDU);
	   connection->Unlock();
  }
}


void MyH323EndPoint::IMOpenSession(const PString & token)
{

  MyH323Connection * connection = (MyH323Connection *)FindConnectionWithLock(token);

  if (connection != NULL) {
	   connection->IMsession = TRUE;
       H323SignalPDU facilityPDU;
       facilityPDU.BuildFacility(*connection, FALSE);
	   connection->WriteSignalPDU(facilityPDU);
	   connection->Unlock();
  }
}
void MyH323EndPoint::IMCloseSession(const PString & token)
{
  MyH323Connection * connection = (MyH323Connection *)FindConnectionWithLock(token);

  if (connection != NULL) {
	   connection->IMsession = FALSE;
       H323SignalPDU facilityPDU;
       facilityPDU.BuildFacility(*connection, FALSE);
	   connection->WriteSignalPDU(facilityPDU);
	   connection->Unlock();
  }
}

void MyH323EndPoint::IMSessionOpen(const PString & token) 
{
	cout << "IM Session Opened" << endl;
}

void MyH323EndPoint::IMSessionClosed(const PString & token) 
{
	cout << "IM Session Closed" << endl;
}

void MyH323EndPoint::IMMessageSent()
{
	cout << "IM Message Sent" << endl;
}

void MyH323EndPoint::IMRegister(const PIPSocket::Address & gateway, 
								const PString & id, 
								const PString & pwd)
{

}

void MyH323EndPoint::IMRegistered(const PString & token)
{

}


///////////////////////////////////////////////////////////////

MyH323Connection::MyH323Connection(MyH323EndPoint & ep, unsigned ref)
  : H323Connection(ep, ref)
{
   IMmsg = PString();
   IMsession = FALSE;
   IMCall = FALSE;

   IMRegID = PString();
   IMRegPwd = PString();
   IMReg = FALSE;
}


BOOL MyH323Connection::OnStartLogicalChannel(H323Channel & channel)
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

void MyH323Connection::OnUserInputString(const PString & value)
{
  cout << "User input received: \"" << value << '"' << endl;
}

BOOL MyH323Connection::OnSendFeatureSet(unsigned code, H225_FeatureSet & feat) const
{
  PTRACE(4,"MyEP\tSend FeatureSet");
   return features.SendFeature(code,feat);
}

void MyH323Connection::OnReceiveFeatureSet(unsigned code, const H225_FeatureSet & feat) const
{
   features.ReceiveFeature(code, feat);
  PTRACE(4,"MyEP\tReceived FeatureSet");
}

// End of File ///////////////////////////////////////////////////////////////

