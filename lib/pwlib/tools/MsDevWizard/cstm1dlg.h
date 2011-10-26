#if !defined(AFX_CSTM1DLG_H__22F027BA_345E_11D2_A1BE_444553540000__INCLUDED_)
#define AFX_CSTM1DLG_H__22F027BA_345E_11D2_A1BE_444553540000__INCLUDED_

// cstm1dlg.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CCustom1Dlg dialog

class CCustom1Dlg : public CAppWizStepDlg
{
// Construction
public:
	CCustom1Dlg();
	virtual BOOL OnDismiss();

// Dialog Data
	//{{AFX_DATA(CCustom1Dlg)
	enum { IDD = IDD_CUSTOM1 };
	CString	m_class_name;
	CString	m_manufacturer;
	CString	m_copyright_holder;
	CString	m_product_name;
	int     m_product_type;
	CString	m_exe_name;
	CString	m_pwlib_dir;
	BOOL    m_use_dlls;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CCustom1Dlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(CCustom1Dlg)
	virtual BOOL OnInitDialog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


//{{AFX_INSERT_LOCATION}}
// Microsoft Developer Studio will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CSTM1DLG_H__22F027BA_345E_11D2_A1BE_444553540000__INCLUDED_)
