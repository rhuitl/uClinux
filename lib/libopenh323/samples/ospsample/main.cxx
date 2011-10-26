/*
 * main.cxx
 *
 * PWLib application source file for OSPSample
 *
 * Main program entry point.
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
 * The Original Code is Portable Windows Library.
 *
 * The Initial Developer of the Original Code is Post Increment
 *
 * This code was written with assistance from TransNexus, Inc.
 * http://www.transnexus.com
 *
 * Contributor(s): ______________________________________.
 *
 * $Log: main.cxx,v $
 * Revision 1.5  2005/01/03 06:25:53  csoutheren
 * Added extensive support for disabling code modules at compile time
 *
 * Revision 1.4  2004/12/20 05:56:33  csoutheren
 * Last check for spelling problems
 *
 * Revision 1.3  2004/12/20 02:33:50  csoutheren
 * Updated for changes to function names
 *
 * Revision 1.2  2004/12/09 23:43:03  csoutheren
 * Added hangup command
 *
 * Revision 1.1  2004/12/08 02:00:59  csoutheren
 * Initial version of OSP sample program
 *
 */

#include "precompile.h"
#include "main.h"
#include "version.h"

#include <opalosp.h>
#include <h323pdu.h>

#define   DEFAULT_OSP_SERVER    "http://osptestserver.transnexus.com:1080/osp"

typedef BOOL (OSPSample::* CmdFunction)(const PStringArray & tokens);

struct CommandInfoType {
  const char * cmd;
  int          minArgCount;
  CmdFunction  function;
  const char * argHelp;
  const char * help;
} Commands[] = {
  { "help",        0,  &OSPSample::CmdHelp      },
  { "status",      0,  &OSPSample::CmdStatus    },

  { "localaddr",   1,  &OSPSample::CmdIPAddress, "ipaddress",                  "set local IP address" },

  { "ospserver",   1,  &OSPSample::CmdServer,    "url [privkey pubkey cakey]", "set OSP server (i.e. http://osptestserver.transnexus.com:1080/osp)" },

  { "call",        2,  &OSPSample::CmdCall,      "srcnum dstnum [callid]",     "make a new outgoing call" },
  { "connect",     0,  &OSPSample::CmdConnect,   NULL,                         "set connect time for a call" },
//  { "validate",  3,  &OSPSample::CmdValidate,  "[srcnum dstnum callid]",     "validate new call (or last call if no parms)" },
  { "hangup",      0,  &OSPSample::CmdHangup,    NULL,                         "hangup the current call" },

  { "quit",        0,  &OSPSample::CmdQuit,      NULL,                         "exit program" },
  { "exit",        0,  &OSPSample::CmdQuit,      NULL,                         "exit program" },

  { NULL }
};

static inline PString StringOrEmpty(const PString & str)
{
  return str.IsEmpty() ? "(empty)" : str;
}

static inline PString DataOrNone(const PBYTEArray & data)
{
  PStringStream str;
  if (data.GetSize() == 0)
    str << "(none)";
  else 
    str << endl << hex << data;

  return str;
}

PCREATE_PROCESS(OSPSample);

OSPSample::OSPSample()
  : PProcess("Post Increment", "ospsample", MAJOR_VERSION, MINOR_VERSION, BUILD_TYPE, BUILD_NUMBER)
{
}

void OSPSample::Main()
{
  PArgList & args = GetArguments();

  args.Parse(
#if PTRACING
             "o-output:"             "-no-output."
             "t-trace."              "-no-trace."
#endif
  );

#if PTRACING
  PTrace::Initialise(args.GetOptionCount('t'),
                     args.HasOption('o') ? (const char *)args.GetOptionString('o') : NULL,
         PTrace::Blocks | PTrace::Timestamp | PTrace::Thread | PTrace::FileAndLine);
#endif

  cout << "OSP Test Program " << GetVersion() << endl;

  // get a plausible local interface address
  PIPSocket::InterfaceTable interfaceTable;
  BOOL foundPublic = FALSE;
  if (PIPSocket::GetInterfaceTable(interfaceTable)) {
    PINDEX i;
    for (i = 0; i < interfaceTable.GetSize(); ++i) {
      PIPSocket::Address addr = interfaceTable[i].GetAddress();
      if (!addr.IsLoopback()) {
        if (!foundPublic || !addr.IsRFC1918())
          localAddr = addr;
      }
    }
  }
  if (!localAddr.IsValid())
    cout << "WARNING: using local host as local address" << endl;
  else
    cout << "Local address is " << localAddr << endl;

  running = TRUE;
  while (running) {
    cout << "Command ? " << flush;
    PString line;
    cin >> line;
    line.Trim();
    PStringArray args = line.Tokenise(' ');
    if (args.GetSize() == 0)
      continue;

    PCaselessString cmd = args[0];
    args.RemoveAt(0);

    CommandInfoType * command = Commands;
    while (command->cmd != NULL) {
      if (cmd == command->cmd)
        break;
      ++command;
    }

    if (command->cmd == NULL) {
      PError << "error: unknown command \"" << cmd << "\"" << endl;
      continue;
    }

    if (args.GetSize() < command->minArgCount) {
      PError << "error: not enough args - " << command->minArgCount << " required" << endl;
      cout << "usage: " << cmd;
      if (command->argHelp != NULL)
        cout << command->argHelp;
      cout << endl;
      continue;
    }

    (this->*command->function)(args);
  }
}

void OSPSample::DisplayResult(const PString & title, int result)
{
  cout << title << " returned error code = " << result << endl;
}


BOOL OSPSample::CmdHelp(const PStringArray & /*args*/)
{
  CommandInfoType * command = Commands;
  while (command->cmd != NULL) {
    cout << command->cmd;
    if (command->argHelp != NULL)
      cout << " " << command->argHelp;
    cout << endl;
    if (command->help != NULL)
      cout << "   " << command->help << endl;
    ++command;
  }
  return TRUE;
}

BOOL OSPSample::CmdStatus(const PStringArray & /*args*/)
{
  if (!provider.IsOpen()) {
    cout << "No provider open" << endl
         << endl;
    return FALSE;
  }

  cout << "Provider open" << endl;

  if (!transaction.IsOpen()) {
    cout << "No transaction open" << endl;
    return FALSE;
  } else {
    cout << "No. of destinations : " << numberOfDestinations << endl
         << "Call ID:              " << DataOrNone(callID) << endl
         << "Call token:           " << DataOrNone(callToken) << endl
         << endl;
  }

  return TRUE;
}

BOOL OSPSample::CmdIPAddress(const PStringArray & args)
{
  localAddr = PIPSocket::Address(args[0]);
  cout << "Local address set to " << localAddr  << endl;
  return TRUE;
}

BOOL OSPSample::CmdQuit(const PStringArray & /*tokens*/)
{
  cout << "Exiting" << endl;
  running = FALSE;
  return TRUE;
}


BOOL OSPSample::CmdServer(const PStringArray & args)
{
  int result;
  if (args.GetSize() < 4)
    result = provider.Open(args[0]);
  else
    result = provider.Open(args[0], args[1], args[2], args[3]);

  DisplayResult("Transaction::Open", result);

  return result == 0;
}

BOOL OSPSample::CmdCall(const PStringArray & args)
{
  int result = 0;
  if (!provider.IsOpen()) {
    cout << "Opening default OSP server " << DEFAULT_OSP_SERVER << endl;
    if (!CmdServer(PStringArray(DEFAULT_OSP_SERVER)))
      return FALSE;
  }

  if (transaction.IsOpen()) {
    cout << "Closing old transaction..." << flush;
    result = CmdHangup(PStringArray());
    DisplayResult("hangup", result);
  }

  cout << "Opening new transaction..." << flush;
  result = transaction.Open(provider);
  if (result != 0) {
    cout << "failed" << endl;
    DisplayResult("Transaction::Open", result);  
    return FALSE;
  }

  PString source(OpalOSP::IpAddressPortToOSPString(localAddr, 1720));
  H225_AliasAddress src, dst;
  H323SetAliasAddress(args[0], src, H225_AliasAddress::e_dialedDigits);
  H323SetAliasAddress(args[1], dst, H225_AliasAddress::e_dialedDigits);

  if (args.GetSize() > 2)
    callID = OpalGloballyUniqueID(args[2]);
  else
    callID = OpalGloballyUniqueID();

  unsigned numberOfDestinations = 10;

  result = transaction.Authorise(
    source, 
    "", 
    src,
    dst,
    callID,
    numberOfDestinations);

  if (result != 0) {
    cout << "failed" << endl;
    DisplayResult("Transaction::Authorise", result);  
    return FALSE;
  }
  
  cout << "returned " << numberOfDestinations << " routeDestinations" << endl;
  if (numberOfDestinations == 0)
    return TRUE;

  result = transaction.GetFirstDestination(timeLimit, callID, calledNumber, routeDestination, device, callToken);
  if (result != 0) {
    DisplayResult("Transaction::GetFirstDestination", result);
    return FALSE;
  }

  cout << "First destination:\n"
    << "  Dest number: " << calledNumber << endl
    << "  Device:      " << StringOrEmpty(device) << endl
    << "  Destination: " << StringOrEmpty(routeDestination) << endl
    << "  Time limit:  " << timeLimit << endl
    << "  Call ID:     " << DataOrNone(callID) << endl
    << "  Token:       " << DataOrNone(callToken) << endl;

  return TRUE;
}

BOOL OSPSample::CmdConnect(const PStringArray & /*tokens*/)
{
  if (!transaction.IsOpen()) {
    PError << "error: no call active" << endl;
    return FALSE;
  }

  transaction.CallConnect(PTime());
  cout << "Connect time set\n";

  return TRUE;
}


BOOL OSPSample::CmdHangup(const PStringArray & /*args*/)
{
  if (!transaction.IsOpen()) {
    PError << "error: no call active" << endl;
    return FALSE;
  }

  transaction.CallEnd();
  transaction.Close();

  cout << "Call hungup\n";
  return TRUE;
}
// End of File ///////////////////////////////////////////////////////////////
