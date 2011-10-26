#if !defined(AFX_MSDEVWIZARDAW_H__22F027AC_345E_11D2_A1BE_444553540000__INCLUDED_)
#define AFX_MSDEVWIZARDAW_H__22F027AC_345E_11D2_A1BE_444553540000__INCLUDED_

// MsDevWizardaw.h : header file
//

class CDialogChooser;

// All function calls made by mfcapwz.dll to this custom AppWizard (except for
//  GetCustomAppWizClass-- see MsDevWizard.cpp) are through this class.  You may
//  choose to override more of the CCustomAppWiz virtual functions here to
//  further specialize the behavior of this custom AppWizard.
class CMsDevWizardAppWiz : public CCustomAppWiz
{
public:
	BOOL m_has_http;
	BOOL m_is_service;
	BOOL m_has_gui;
	BOOL m_use_dlls;
	CString m_pwlib_dir;
	virtual CAppWizStepDlg* Next(CAppWizStepDlg* pDlg);
	virtual CAppWizStepDlg* Back(CAppWizStepDlg* pDlg);
		
	virtual void InitCustomAppWiz();
	virtual void ExitCustomAppWiz();
	virtual void CustomizeProject(IBuildProject* pProject);

protected:
	CDialogChooser* m_pChooser;
};

// This declares the one instance of the CMsDevWizardAppWiz class.  You can access
//  m_Dictionary and any other public members of this class through the
//  global MsDevWizardaw.  (Its definition is in MsDevWizardaw.cpp.)
extern CMsDevWizardAppWiz MsDevWizardaw;

//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MSDEVWIZARDAW_H__22F027AC_345E_11D2_A1BE_444553540000__INCLUDED_)
