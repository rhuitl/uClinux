/*
 * main.h
 *
 * PWLib application header file for OSPSample
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
 * $Log: main.h,v $
 * Revision 1.3  2004/12/20 05:56:33  csoutheren
 * Last check for spelling problems
 *
 * Revision 1.2  2004/12/09 23:43:03  csoutheren
 * Added hangup command
 *
 * Revision 1.1  2004/12/08 02:00:59  csoutheren
 * Initial version of OSP sample program
 *
 */

#ifndef _OSPSample_MAIN_H
#define _OSPSample_MAIN_H

#include <opalosp.h>

class OSPSample : public PProcess
{
  PCLASSINFO(OSPSample, PProcess)

  public:
    OSPSample();
    virtual void Main();

    BOOL CmdHelp(const PStringArray & tokens);    
    BOOL CmdStatus(const PStringArray & tokens);    

    BOOL CmdKey(const PStringArray & tokens);    
    BOOL CmdCert(const PStringArray & tokens);
    BOOL CmdAuthCert(const PStringArray & tokens);
    BOOL CmdServer(const PStringArray & tokens);
    BOOL CmdCall(const PStringArray & tokens);
    BOOL CmdConnect(const PStringArray & tokens);
    BOOL CmdIPAddress(const PStringArray & tokens);
    BOOL CmdQuit(const PStringArray & tokens);
    BOOL CmdHangup(const PStringArray & tokens);

    void DisplayResult(const PString & title, int result);

  protected:
    PIPSocket::Address localAddr;
    OpalOSP::Provider provider;
    OpalOSP::Transaction transaction;

    BOOL running;

    PBYTEArray callID;
    PBYTEArray callToken;
    unsigned numberOfDestinations;

    unsigned timeLimit;
    PString calledNumber;
    PString routeDestination;
    PString device;
};

#endif  // _OSPSample_MAIN_H


// End of File ///////////////////////////////////////////////////////////////
