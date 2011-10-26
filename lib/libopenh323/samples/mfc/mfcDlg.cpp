// mfcDlg.cpp : implementation file
//

#include "stdafx.h"
#include "mfc.h"
#include "mfcDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CMfcDlg dialog

CMfcDlg::CMfcDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CMfcDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CMfcDlg)
	m_destination = _T("");
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMfcDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CMfcDlg)
	DDX_Control(pDX, IDC_CALLER, m_caller);
	DDX_Control(pDX, IDC_REFUSE, m_refuse);
	DDX_Control(pDX, IDC_HANGUP, m_hangup);
	DDX_Control(pDX, IDC_ANSWER, m_answer);
	DDX_Control(pDX, IDC_CALL, m_call);
	DDX_Text(pDX, IDC_DESTINATION, m_destination);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CMfcDlg, CDialog)
	//{{AFX_MSG_MAP(CMfcDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_CALL, OnCall)
	ON_BN_CLICKED(IDC_ANSWER, OnAnswer)
	ON_BN_CLICKED(IDC_REFUSE, OnRefuse)
	ON_BN_CLICKED(IDC_HANGUP, OnHangup)
	ON_EN_CHANGE(IDC_DESTINATION, OnChangeDestination)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CMfcDlg message handlers

BOOL CMfcDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

        m_endpoint.Initialise(this);
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CMfcDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CMfcDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CMfcDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CMfcDlg::OnCall() 
{
  m_endpoint.MakeCall((const char *)m_destination, m_token);
  m_call.EnableWindow(FALSE);
  m_hangup.EnableWindow();
}

void CMfcDlg::OnAnswer() 
{
  m_caller.SetWindowText("");
  m_answer.EnableWindow(FALSE);
  m_refuse.EnableWindow(FALSE);
  m_hangup.EnableWindow(FALSE);
  m_call.EnableWindow();

  H323Connection * connection = m_endpoint.FindConnectionWithLock(m_token);
  if (connection == NULL)
    m_call.EnableWindow();
  else {
    connection->AnsweringCall(H323Connection::AnswerCallNow);
    connection->Unlock();
  }
}

void CMfcDlg::OnRefuse() 
{
  m_caller.SetWindowText("");
  m_answer.EnableWindow(FALSE);
  m_refuse.EnableWindow(FALSE);
  m_hangup.EnableWindow(FALSE);

  H323Connection * connection = m_endpoint.FindConnectionWithLock(m_token);
  if (connection == NULL)
    m_call.EnableWindow();
  else {
    connection->AnsweringCall(H323Connection::AnswerCallDenied);
    connection->Unlock();
  }
}

void CMfcDlg::OnHangup() 
{
  m_endpoint.ClearCall(m_token);
  m_hangup.EnableWindow(FALSE);
  m_call.EnableWindow();
}

void CMfcDlg::OnChangeDestination() 
{
  UpdateData();
  m_call.EnableWindow(!m_destination.IsEmpty());
}
