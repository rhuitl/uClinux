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

#ifndef _MyH323_MAIN_H
#define _MyH323_MAIN_H

#include <h323.h>
#include <H4601.h>


class MyH323EndPoint : public H323EndPoint
{
  PCLASSINFO(MyH323EndPoint, H323EndPoint);

  public:
    MyH323EndPoint();
    ~MyH323EndPoint();

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

/////////////////////////////////////////////
// OID1 Stuff

	// Overrides from H323EndPoint
	virtual BOOL OnSendFeatureSet(unsigned id, H225_FeatureSet & Message);
	virtual void OnReceiveFeatureSet(unsigned id, const H225_FeatureSet & Message);

	virtual BOOL OnSendCallIndependentSupplementaryService(const H323Connection * connection,
                     H323SignalPDU & pdu);
	virtual BOOL OnReceiveCallIndependentSupplementaryService(const H323Connection * connection,
                     const H323SignalPDU & pdu);


    // Methods
	virtual void SendIM(const PString & token, const PString & msg);
	virtual void IMOpenSession(const PString & token);
	virtual void IMCloseSession(const PString & token);

	virtual void IMRegister(const PIPSocket::Address & gateway, 
							const PString & id, 
							const PString & pwd);

	// Events
	virtual void IMSessionOpen(const PString & token);
	virtual void IMSessionClosed(const PString & token);
	virtual void IMMessageSent();
	virtual void ReceivedIM(const PString & token, const PString & msg);
	virtual void SupportsIM(const PString & token);

	virtual void IMRegistered(const PString & token);

    BOOL IMCall;
	BOOL IMsession;
	PString IMmsg;

/////////////////////////////////////////////

  protected:
    BOOL autoAnswer;
    PString busyForwardParty;
};


class MyH323Connection : public H323Connection
{
    PCLASSINFO(MyH323Connection, H323Connection);

  public:
    MyH323Connection(MyH323EndPoint &, unsigned);

    virtual BOOL OnStartLogicalChannel(H323Channel &);
    virtual void OnUserInputString(const PString &);

    virtual BOOL OnSendFeatureSet(unsigned, H225_FeatureSet &) const;
    virtual void OnReceiveFeatureSet(unsigned, const H225_FeatureSet &) const;

	virtual void SetCallAnswered() { callAnswered = TRUE; };


	PString IMmsg;
	BOOL IMsession;
	BOOL IMCall;
	PString IMRegID;
	PString IMRegPwd;
	BOOL IMReg;

  protected:
    BOOL noFastStart;



};


class MyH323Process : public PProcess
{
  PCLASSINFO(MyH323Process, PProcess)

  public:
    MyH323Process();
    ~MyH323Process();

    void Main();

  protected:
    MyH323EndPoint * endpoint;
};


#endif  // _MyH323_MAIN_H


// End of File ///////////////////////////////////////////////////////////////
