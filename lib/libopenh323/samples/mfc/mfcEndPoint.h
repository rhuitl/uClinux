// MfcEndPoint.h: interface for the CMfcEndPoint class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_MFCENDPOINT_H__B1AF53B8_E3C6_4590_BBC8_6614922EC493__INCLUDED_)
#define AFX_MFCENDPOINT_H__B1AF53B8_E3C6_4590_BBC8_6614922EC493__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <h323.h>

class CMfcDlg;

class CMfcEndPoint : public H323EndPoint  
{
public:
	virtual H323Connection::AnswerCallResponse OnAnswerCall(H323Connection &, const PString & caller,const H323SignalPDU &,H323SignalPDU &);
	virtual void OnConnectionEstablished(H323Connection & connection, const PString & token);
	virtual void OnConnectionCleared(H323Connection & connection, const PString & clearedCallToken);
	BOOL Initialise(CMfcDlg * dlg);
	virtual H323Connection * CreateConnection(unsigned refID);
	CMfcEndPoint();
	virtual ~CMfcEndPoint();
protected:
	CMfcDlg * m_dialog;
};

#endif // !defined(AFX_MFCENDPOINT_H__B1AF53B8_E3C6_4590_BBC8_6614922EC493__INCLUDED_)
