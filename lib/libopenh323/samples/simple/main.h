/*
 * main.h
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
 * $Log: main.h,v $
 * Revision 1.8  2001/11/01 01:35:25  robertj
 * Added default Fast Start disabled and H.245 tunneling disable flags
 *   to the endpoint instance.
 *
 * Revision 1.7  2001/08/06 03:18:35  robertj
 * Fission of h323.h to h323ep.h & h323con.h, h323.h now just includes files.
 * Improved access to H.235 secure RAS functionality.
 * Changes to H.323 secure RAS contexts to help use with gk server.
 *
 * Revision 1.6  2001/08/03 11:56:26  robertj
 * Added conditional compile for H.235 stuff.
 *
 * Revision 1.5  2001/03/21 04:52:40  robertj
 * Added H.235 security to gatekeepers, thanks Fürbass Franz!
 *
 * Revision 1.4  2001/03/20 23:42:55  robertj
 * Used the new PTrace::Initialise function for starting trace code.
 *
 * Revision 1.3  2000/07/31 14:08:09  robertj
 * Added fast start and H.245 tunneling flags to the H323Connection constructor so can
 *    disabled these features in easier manner to overriding virtuals.
 *
 * Revision 1.2  2000/06/07 05:47:56  robertj
 * Added call forwarding.
 *
 * Revision 1.1  2000/05/11 04:05:57  robertj
 * Simple sample program.
 *
 */

#ifndef _SimpleH323_MAIN_H
#define _SimpleH323_MAIN_H

#include <h323.h>


class SimpleH323EndPoint : public H323EndPoint
{
  PCLASSINFO(SimpleH323EndPoint, H323EndPoint);

  public:
    SimpleH323EndPoint();
    ~SimpleH323EndPoint();

    // overrides from H323EndPoint
    virtual H323Connection * CreateConnection(unsigned callReference);
    virtual BOOL OnIncomingCall(H323Connection &, const H323SignalPDU &, H323SignalPDU &);
    virtual H323Connection::AnswerCallResponse OnAnswerCall(H323Connection &, const PString &, const H323SignalPDU &, H323SignalPDU &);
    virtual BOOL OnConnectionForwarded(H323Connection &, const PString &, const H323SignalPDU &);
    virtual void OnConnectionEstablished(H323Connection & connection, const PString & token);
    virtual void OnConnectionCleared(H323Connection & connection, const PString & clearedCallToken);
    virtual BOOL OpenAudioChannel(H323Connection &, BOOL, unsigned, H323AudioCodec &);

    // New functions
    BOOL Initialise(PArgList &);
    BOOL SetSoundDevice(PArgList &, const char *, PSoundChannel::Directions);

    PString currentCallToken;

  protected:
    BOOL autoAnswer;
    PString busyForwardParty;
};


class SimpleH323Connection : public H323Connection
{
    PCLASSINFO(SimpleH323Connection, H323Connection);

  public:
    SimpleH323Connection(SimpleH323EndPoint &, unsigned);

    virtual BOOL OnStartLogicalChannel(H323Channel &);
    virtual void OnUserInputString(const PString &);

  protected:
    BOOL noFastStart;
};


class SimpleH323Process : public PProcess
{
  PCLASSINFO(SimpleH323Process, PProcess)

  public:
    SimpleH323Process();
    ~SimpleH323Process();

    void Main();

  protected:
    SimpleH323EndPoint * endpoint;
};


#endif  // _SimpleH323_MAIN_H


// End of File ///////////////////////////////////////////////////////////////
