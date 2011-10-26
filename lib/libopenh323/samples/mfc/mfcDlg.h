// mfcDlg.h : header file
//

#if !defined(AFX_MFCDLG_H__D73EA34B_CCAF_4862_840F_E7EA0162585D__INCLUDED_)
#define AFX_MFCDLG_H__D73EA34B_CCAF_4862_840F_E7EA0162585D__INCLUDED_

#include "MfcEndPoint.h"	// Added by ClassView
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CMfcDlg dialog

class CMfcDlg : public CDialog
{
// Construction
public:
	PString m_token;
	CMfcEndPoint m_endpoint;
	CMfcDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CMfcDlg)
	enum { IDD = IDD_MFC_DIALOG };
	CStatic	m_caller;
	CButton	m_refuse;
	CButton	m_hangup;
	CButton	m_answer;
	CButton	m_call;
	CString	m_destination;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMfcDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CMfcDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnCall();
	afx_msg void OnAnswer();
	afx_msg void OnRefuse();
	afx_msg void OnHangup();
	afx_msg void OnChangeDestination();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MFCDLG_H__D73EA34B_CCAF_4862_840F_E7EA0162585D__INCLUDED_)
