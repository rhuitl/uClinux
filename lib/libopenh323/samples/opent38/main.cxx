/*
 * main.cxx
 *
 * Version number header file for simple OpenH323 sample T.38 transmitter.
 *
 * Copyright (c) 2001 Equivalence Pty. Ltd.
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
 * Revision 1.6  2002/04/17 03:51:21  robertj
 * Fixed correct function override, thanks Suk Tong Hoon
 *
 * Revision 1.5  2001/12/22 03:35:52  robertj
 * Added create protocol function to H323Connection.
 *
 * Revision 1.4  2001/12/22 01:57:46  robertj
 * Added file lines to trace output.
 * Added creation of T.38 rotocol handler.
 *
 * Revision 1.3  2001/12/20 04:10:06  robertj
 * More T.38 testing
 *
 * Revision 1.2  2001/12/13 11:07:03  robertj
 * More implementation
 *
 */

#include <ptlib.h>

#include "main.h"
#include "version.h"

#include <h323ep.h>
#include <h323t38.h>


PCREATE_PROCESS(T38App);


///////////////////////////////////////////////////////////////

T38App::T38App()
	: PProcess("Open H323 Project", "OpenT38", 
		MAJOR_VERSION, MINOR_VERSION, BUILD_TYPE, BUILD_NUMBER)
{
}


void T38App::Main()
{
  PArgList & args = GetArguments();

  args.Parse(
    "t-trace."
    "o-output:"
    "-tcp."
    "-udp."
    "u:"
    "F."
    "l-listen."
    , FALSE);

  PString destAddr;
  if (!args.HasOption('l')) {
    if (args.GetCount() < 1) {
      cout << "usage: " << GetName() << " [options] destaddr" << endl
           << "where options are:" << endl
           << "  -t    enable tracing" << endl
           << "  -o    output tracing to file" << endl
	   << "  -u    set local username" << endl
	   << "  --udp enable UDP transport" << endl
	   << "  --tcp enable TCP transport" << endl
	   << "  -F    disable fastStart" << endl;

      return;
    }

    destAddr = args[0];
  }

  PTrace::Initialise(args.GetOptionCount('t'),
	                   args.HasOption('o') ? (const char *)args.GetOptionString('o') : NULL,
                           PTrace::Timestamp|PTrace::Thread|PTrace::FileAndLine);

  T38EndPoint endpoint(destAddr.IsEmpty());
  if (args.HasOption('u'))
    endpoint.SetLocalUserName(args.GetOptionString('u'));

  endpoint.AddAllCapabilities(0, 0, "G.711*{sw}");

  H323_T38Capability::TransportMode transportMode = H323_T38Capability::e_UDP;
  if (args.HasOption("udp"))
    transportMode = H323_T38Capability::e_UDP;
  else if (args.HasOption("tcp"))
    transportMode = H323_T38Capability::e_SingleTCP;

  endpoint.SetCapability(0, 1, new H323_T38Capability(transportMode));

  if (args.HasOption('F'))
    endpoint.DisableFastStart(TRUE);

  if (destAddr.IsEmpty()) {
    if (!endpoint.StartListener("*")) {
      PTRACE(1, "Could not start listener");
      cerr << "Could not start listener";
      return;
    }

    cout << "Awaiting call..." << ::flush;
    Sleep(PMaxTimeInterval);
  }
  else {
    PTRACE(1, "Making the call...");

    PString token;
    endpoint.MakeCall(destAddr, token);
    while (endpoint.HasConnection(token))
      Sleep(1000);
  }
}


///////////////////////////////////////////////////////////////

T38EndPoint::T38EndPoint(BOOL rx)
{
  autoStartReceiveFax = rx;
  autoStartTransmitFax = !rx;
}


OpalT38Protocol * T38EndPoint::CreateT38ProtocolHandler(const H323Connection &) const
{
  return new OpalT38Protocol();
}


// End of File ///////////////////////////////////////////////////////////////
