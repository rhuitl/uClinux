// MsDevWizard.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include <afxdllx.h>
#include "MsDevWizard.h"
#include "MsDevWizardaw.h"

#ifdef _PSEUDO_DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

static AFX_EXTENSION_MODULE MsDevWizardDLL = { NULL, NULL };

extern "C" int APIENTRY
DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		TRACE0("MSDEVWIZARD.AWX Initializing!\n");
		
		// Extension DLL one-time initialization
		AfxInitExtensionModule(MsDevWizardDLL, hInstance);

		// Insert this DLL into the resource chain
		new CDynLinkLibrary(MsDevWizardDLL);

		// Register this custom AppWizard with MFCAPWZ.DLL
		SetCustomAppWizClass(&MsDevWizardaw);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		TRACE0("MSDEVWIZARD.AWX Terminating!\n");

		// Terminate the library before destructors are called
		AfxTermExtensionModule(MsDevWizardDLL);
	}
	return 1;   // ok
}
