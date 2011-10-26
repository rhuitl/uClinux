// cstm1dlg.cpp : implementation file
//

#include "stdafx.h"
#include "MsDevWizard.h"
#include "cstm1dlg.h"
#include "MsDevWizardaw.h"

#include <stdlib.h>
#include <time.h>
#include <io.h>

#ifdef _PSEUDO_DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CCustom1Dlg dialog


CCustom1Dlg::CCustom1Dlg()
	: CAppWizStepDlg(CCustom1Dlg::IDD)
{
	//{{AFX_DATA_INIT(CCustom1Dlg)
	m_class_name = _T("");
	m_manufacturer = _T("Equivalence");
	m_copyright_holder = _T("Equivalence Pty. Ltd.");
	m_product_name = _T("");
	m_product_type = 0;
	m_exe_name = _T("");
	m_pwlib_dir = _T("");
	m_use_dlls = TRUE;
	//}}AFX_DATA_INIT
}


void CCustom1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CAppWizStepDlg::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CCustom1Dlg)
	DDX_Text(pDX, IDC_CLASS_NAME, m_class_name);
	DDX_Text(pDX, IDC_MANUFACTURER, m_manufacturer);
	DDX_Text(pDX, IDC_COPYRIGHT_HOLDER, m_copyright_holder);
	DDX_Text(pDX, IDC_PRODUCT_NAME, m_product_name);
	DDX_Radio(pDX, IDC_TEXT_ONLY, m_product_type);
	DDX_Text(pDX, IDC_EXE_NAME, m_exe_name);
	DDX_Text(pDX, IDC_PWLIB_DIR, m_pwlib_dir);
	DDX_Check(pDX, IDC_USE_DLL, m_use_dlls);
	//}}AFX_DATA_MAP
}

static void SetDictionaryKey(const char * key, BOOL value)
{
  if (value)
    MsDevWizardaw.m_Dictionary[key] = key;
  else
    MsDevWizardaw.m_Dictionary.RemoveKey(key);
}

// This is called whenever the user presses Next, Back, or Finish with this step
//  present.  Do all validation & data exchange from the dialog in this function.
BOOL CCustom1Dlg::OnDismiss()
{
	if (!UpdateData(TRUE))
		return FALSE;

        // Strip .exe off end of string (if there is one)
        CString lower_exe = m_exe_name;
        lower_exe.MakeLower();
        int pos = lower_exe.Find(".exe");
        if (pos >= 0)
          m_exe_name = m_exe_name.Mid(pos);

        static const struct {
          const char * product_type;
          const char * parent_app_class;
          const char * parent_win_class;
          const char * header_file;
          BOOL is_gui;
          BOOL is_service;
          BOOL has_http;
          BOOL has_signature;
        } product_type_strings[] = {
          { "Text Only", "PProcess",            "",                "ptlib.h", FALSE, FALSE, FALSE, FALSE },
          { "GUI",       "PApplication",        "PTopLevelWindow", "pwlib.h", TRUE,  FALSE, FALSE, FALSE },
          { "GUI",       "PApplication",        "PMDIFrameWindow", "pwlib.h", TRUE,  FALSE, FALSE, FALSE },
          { "Service",   "PServiceProcess",     "",                "ptlib.h", FALSE, TRUE,  FALSE, FALSE },
          { "Service",   "PHTTPServiceProcess", "",                "ptlib.h", FALSE, TRUE,  TRUE,  FALSE },
          { "Service",   "PHTTPServiceProcess", "",                "ptlib.h", FALSE, TRUE,  TRUE,  TRUE  }
        };

	MsDevWizardaw.m_Dictionary["PRODUCT_TYPE"] = product_type_strings[m_product_type].product_type;
	MsDevWizardaw.m_Dictionary["PRODUCT_NAME"] = m_product_name;
	MsDevWizardaw.m_Dictionary["MANUFACTURER"] = m_manufacturer;
	MsDevWizardaw.m_Dictionary["COPYRIGHT_HOLDER"] = m_copyright_holder;
	MsDevWizardaw.m_Dictionary["EXE_NAME"] = m_exe_name;
	MsDevWizardaw.m_Dictionary["APP_CLASS_NAME"] = m_class_name;
	MsDevWizardaw.m_Dictionary["PARENT_APP_CLASS"] = product_type_strings[m_product_type].parent_app_class;
	MsDevWizardaw.m_Dictionary["PARENT_WIN_CLASS"] = product_type_strings[m_product_type].parent_win_class;
	MsDevWizardaw.m_Dictionary["HEADER_FILE"] = product_type_strings[m_product_type].header_file;
        SetDictionaryKey("IS_GUI", product_type_strings[m_product_type].is_gui);
        SetDictionaryKey("IS_SERVICE", product_type_strings[m_product_type].is_service);
        SetDictionaryKey("HAS_HTTP", product_type_strings[m_product_type].has_http);
        SetDictionaryKey("HAS_SIGNATURE", product_type_strings[m_product_type].has_signature);

        srand(clock());
	MsDevWizardaw.m_Dictionary["SIGNATURE_KEY"].Format(
                        "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u",
                        rand()&255, rand()&255, rand()&255, rand()&255,
                        rand()&255, rand()&255, rand()&255, rand()&255,
                        rand()&255, rand()&255, rand()&255, rand()&255,
                        rand()&255, rand()&255, rand()&255, rand()&255);
	MsDevWizardaw.m_Dictionary["APPLICATION_KEY"].Format(
                        "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u",
                        rand()&255, rand()&255, rand()&255, rand()&255,
                        rand()&255, rand()&255, rand()&255, rand()&255,
                        rand()&255, rand()&255, rand()&255, rand()&255,
                        rand()&255, rand()&255, rand()&255, rand()&255);

        MsDevWizardaw.m_has_gui = product_type_strings[m_product_type].is_gui;
        MsDevWizardaw.m_is_service = product_type_strings[m_product_type].is_service;
        MsDevWizardaw.m_has_http = product_type_strings[m_product_type].has_http;
        MsDevWizardaw.m_use_dlls = m_use_dlls;
        MsDevWizardaw.m_pwlib_dir = m_pwlib_dir;

	return TRUE;	// return FALSE if the dialog shouldn't be dismissed
}


BEGIN_MESSAGE_MAP(CCustom1Dlg, CAppWizStepDlg)
	//{{AFX_MSG_MAP(CCustom1Dlg)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CCustom1Dlg message handlers

BOOL CCustom1Dlg::OnInitDialog() 
{
	CAppWizStepDlg::OnInitDialog();
	
	m_class_name = MsDevWizardaw.m_Dictionary["Safe_root"];
	m_product_name = MsDevWizardaw.m_Dictionary["Root"];
	m_exe_name = MsDevWizardaw.m_Dictionary["Root"];

        m_pwlib_dir = "";
        CString full_dir = MsDevWizardaw.m_Dictionary["FULL_DIR_PATH"];
        full_dir.MakeLower();
        int pos;
        if ((pos = full_dir.Find("\\pwlib\\")) >= 0) {
          pos += 6;
          do {
            full_dir = full_dir.Mid(pos+1);
            if (!full_dir.IsEmpty())
              m_pwlib_dir += "..\\";
          } while ((pos = full_dir.Find('\\')) >= 0);
        }
        else {
          const char * pwlib_dir = getenv("PWLIB_DIR");
          if (pwlib_dir == NULL)
            pwlib_dir = "c:\\pwlib";
          if (_access(pwlib_dir, 0) == 0)
            m_pwlib_dir = pwlib_dir;
        }

        UpdateData(FALSE);

	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}
