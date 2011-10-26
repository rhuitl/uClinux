// mfc.h : main header file for the MFC application
//

#if !defined(AFX_MFC_H__A1FF011A_641B_44F1_8897_1615CE1DFF7A__INCLUDED_)
#define AFX_MFC_H__A1FF011A_641B_44F1_8897_1615CE1DFF7A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CMfcApp:
// See mfc.cpp for the implementation of this class
//

class CMfcApp : public CWinApp
{
public:
	CMfcApp();

/**** Open H323 Start ****/
        class PWLibProcess : public PProcess {
          PCLASSINFO(PWLibProcess, PProcess);
          void Main() { }
        } pwlibProcess;
/**** Open H323 End ****/

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMfcApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CMfcApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MFC_H__A1FF011A_641B_44F1_8897_1615CE1DFF7A__INCLUDED_)
