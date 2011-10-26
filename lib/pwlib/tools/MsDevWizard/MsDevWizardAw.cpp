// MsDevWizardaw.cpp : implementation file
//

#include "stdafx.h"
#include "MsDevWizard.h"
#include "MsDevWizardaw.h"
#include "chooser.h"

#include <comdef.h>
#include <atlbase.h>
#include <fstream.h>
#include <string.h>
#include <objmodel/bldauto.h>

#ifdef _PSEUDO_DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// This is called immediately after the custom AppWizard is loaded.  Initialize
//  the state of the custom AppWizard here.
void CMsDevWizardAppWiz::InitCustomAppWiz()
{
	// Create a new dialog chooser; CDialogChooser's constructor initializes
	//  its internal array with pointers to the steps.
	m_pChooser = new CDialogChooser;

	// Set the maximum number of steps.
	SetNumberOfSteps(LAST_DLG);

	// TODO: Add any other custom AppWizard-wide initialization here.
}

static void MakeCustomBuild(const char * config, ostream & out)
{
  out << "IF  \"$(CFG)\" == \"" << MsDevWizardaw.m_Dictionary["Root"] << " - Win32 " << config << "\"\n"
         "\n"
         "# Begin Custom Build - Building event log resources.\n"
         "InputDir=.\n"
         "IntDir=.\\Release\n"
         "TargetName=" << MsDevWizardaw.m_Dictionary["Root"] << "\n"
         "InputPath=.\\messages.mc\n"
         "InputName=messages\n"
         "\n"
         "BuildCmds= \\\n"
	 "\tmc -h $(IntDir) -r $(IntDir) $(InputPath) \\\n"
	 "\techo 1 ICON $(InputDir)\\$(TargetName).ico >> $(IntDir)\\$(InputName).rc \\\n";
  if (MsDevWizardaw.m_has_http)
    out << "\techo RCINCLUDE $(InputDir)\\custom.cxx >> $(IntDir)\\$(InputName).rc \\\n";
  out << "\trc -i$(IntDir) -fo$(IntDir)\\$(InputName).res $(IntDir)\\$(InputName).rc \\\n"
         "\n"
         "\n"
         "\"$(IntDir)\\$(InputName).h\" : $(SOURCE) \"$(INTDIR)\" \"$(OUTDIR)\"\n"
         "\t$(BuildCmds)\n"
         "\n"
         "\"$(IntDir)\\$(InputName).rc\" : $(SOURCE) \"$(INTDIR)\" \"$(OUTDIR)\"\n"
         "\t$(BuildCmds)\n"
         "\n"
         "\"$(IntDir)\\MSG00001.bin\" : $(SOURCE) \"$(INTDIR)\" \"$(OUTDIR)\"\n"
         "\t$(BuildCmds)\n"
         "\n"
         "\"$(IntDir)\\$(InputName).res\" : $(SOURCE) \"$(INTDIR)\" \"$(OUTDIR)\"\n"
         "\t$(BuildCmds)\n"
         "# End Custom Build\n\n";
}

static void MakeResourceBuild(const char * config, ostream & out)
{
  out << "IF  \"$(CFG)\" == \"" << MsDevWizardaw.m_Dictionary["Root"] << " - Win32 " << config << "\"\n"
         "\n"
         "# Begin Custom Build - Building resources.\n"
         "InputDir=.\n"
         "IntDir=.\\Release\n"
         "InputPath=.\\resources.prc\n"
         "InputName=resources\n"
         "\n"
         "BuildCmds= \\\n"
	 "\tpwrc -I \"$(Include)\" "
                "-o $(IntDir)\\$(InputName).res "
                "-b $(InputName) $(InputPath)\n"
         "\n"
         "\"$(InputDir)\\$(InputName).h\" : $(SOURCE) \"$(INTDIR)\" \"$(OUTDIR)\"\n"
         "\t$(BuildCmds)\n"
         "\n"
         "\"$(InputDir)\\$(InputName).cxx\" : $(SOURCE) \"$(INTDIR)\" \"$(OUTDIR)\"\n"
         "\t$(BuildCmds)\n"
         "\n"
         "\"$(IntDir)\\$(InputName).res\" : $(SOURCE) \"$(INTDIR)\" \"$(OUTDIR)\"\n"
         "\t$(BuildCmds)\n"
         "# End Custom Build\n\n";
}

// This is called just before the custom AppWizard is unloaded.
void CMsDevWizardAppWiz::ExitCustomAppWiz()
{
  // Deallocate memory used for the dialog chooser
  ASSERT(m_pChooser != NULL);
  delete m_pChooser;
  m_pChooser = NULL;

  CString dsp_name = m_Dictionary["FULL_DIR_PATH"];
  if (dsp_name[dsp_name.GetLength()-1] != '\\')
    dsp_name += "\\";
  dsp_name += m_Dictionary["Root"] + ".dsp";
  CString dsp_name2 = dsp_name + "$";

  ifstream in = dsp_name;
  ofstream out = dsp_name2;

  if (!in.is_open() || !out.is_open()) {
    AfxMessageBox(IDS_PROJ_REWRITE);
    return;
  }

  char line[1000];
  while (!in.eof()) {
    in.getline(line, sizeof(line));
    if (strcmp(line, "# PROP BASE Use_MFC 2") == 0)
      out << "# PROP BASE Use_MFC 0\n";
    else if (strcmp(line, "# PROP Use_MFC 2") == 0)
      out << "# PROP Use_MFC 0\n";
    else if (strcmp(line, "SOURCE=.\\precompile.cxx") == 0)
      out << line << "\n# ADD CPP /Yc\"precompile.h\"\n";
    else if (strcmp(line, "SOURCE=.\\custom.cxx") == 0)
      out << line << "\n# SUBTRACT CPP /YX /Yc /Yu\n";
    else if (strcmp(line, "SOURCE=.\\messages.mc") == 0) {
      out << line << "\n\n!";
      MakeCustomBuild("Release", out);
      out << "!ELSE";
      MakeCustomBuild("Debug", out);
      out << "!ENDIF\n\n";
    }
    else if (strcmp(line, "SOURCE=.\\resources.prc") == 0) {
      out << "SOURCE=.\\resources.cxx\n"
             "# End Source File\n"
             "# Begin Source File\n"
             "\n"
          << line << "\n\n!";
      MakeResourceBuild("Release", out);
      out << "!ELSE";
      MakeResourceBuild("Debug", out);
      out << "!ENDIF\n\n";
    }
    else
      out << line << '\n';
  }

  out.flush();
  out.close();
  in.close();

  if (remove(dsp_name) < 0)
    AfxMessageBox(IDS_PROJ_REWRITE);
  else if (rename(dsp_name2, dsp_name) < 0)
    AfxMessageBox(IDS_PROJ_REWRITE);
}

// This is called when the user clicks "Create..." on the New Project dialog
//  or "Next" on one of the custom AppWizard's steps.
CAppWizStepDlg* CMsDevWizardAppWiz::Next(CAppWizStepDlg* pDlg)
{
	// Delegate to the dialog chooser
	return m_pChooser->Next(pDlg);
}

// This is called when the user clicks "Back" on one of the custom
//  AppWizard's steps.
CAppWizStepDlg* CMsDevWizardAppWiz::Back(CAppWizStepDlg* pDlg)
{
	// Delegate to the dialog chooser
	return m_pChooser->Back(pDlg);
}

#import "ide\devbld.pkg"

void CMsDevWizardAppWiz::CustomizeProject(IBuildProject* pProject)
{
  CString c_settings = "/Yu\"precompile.h\" /W4 ";
  CString l_settings = "comdlg32.lib winspool.lib wsock32.lib mpr.lib "
                       "kernel32.lib user32.lib gdi32.lib shell32.lib advapi32.lib ";

  if (!m_pwlib_dir.IsEmpty()) {
    if (m_pwlib_dir[m_pwlib_dir.GetLength()-1] != '\\')
      m_pwlib_dir += "\\";
    c_settings += "/I \"" + m_pwlib_dir + "include\\pwlib\\mswin\" "
                  "/I \"" + m_pwlib_dir + "include\\ptlib\\msos\" "
                  "/I \"" + m_pwlib_dir + "include\" ";
    l_settings += "/libpath:" + m_pwlib_dir + "lib ";
  }

  if (!m_has_gui && !m_is_service)
    l_settings += " /subsystem:console";


  // Needed to convert IBuildProject to the DSProjectSystem namespace
  using namespace DSProjectSystem;
  IBuildProjectPtr pProj;
  pProj.Attach((DSProjectSystem::IBuildProject*)pProject, true);

  IConfigurationsPtr pConfigs;
  if (pProj->get_Configurations(&pConfigs) != S_OK) {
    AfxMessageBox(IDS_PROJ_ERROR);
    return;
  }

  long count;
  if (pConfigs->get_Count(&count) != S_OK) {
    AfxMessageBox(IDS_PROJ_ERROR);
    return;
  }

  while (count > 0) {
    COleVariant index = count;
    IConfigurationPtr pConfig = pConfigs->Item(index);

    BSTR name;
    pConfig->get_Name(&name);
    static _bstr_t debug_str = "Debug";
    BOOL is_debug = wcsstr(name, debug_str) != NULL;
    COleVariant reserved(0L, VT_ERROR);
    reserved.scode = DISP_E_PARAMNOTFOUND;

    static _bstr_t cl_exe = "cl.exe";
    _bstr_t settings_bstr = "/D \"_AFXDLL\"";
    if (pConfig->RemoveToolSettings(cl_exe, settings_bstr, reserved) != S_OK) {
      AfxMessageBox(IDS_PROJ_ERROR);
      return;
    }

    settings_bstr = c_settings;
    if (pConfig->AddToolSettings(cl_exe, settings_bstr, reserved) != S_OK) {
      AfxMessageBox(IDS_PROJ_ERROR);
      return;
    }

    CString settings;
    if (m_has_gui) {
      settings = "pwclib";
      if (is_debug) // Debug configuration
        settings += "d";
      settings += ".lib pwlib";
      if (!m_use_dlls)
        settings += "s";
      if (is_debug) // Debug configuration
        settings += "d";
      settings += ".lib ";
    }
    settings += "ptclib";
    if (is_debug) // Debug configuration
      settings += "d";
    settings += ".lib ptlib";
    if (!m_use_dlls)
      settings += "s";
    if (is_debug) // Debug configuration
      settings += "d";
    settings += ".lib " + l_settings;
    static _bstr_t link_exe = "link.exe";
    settings_bstr = settings;
    if (pConfig->AddToolSettings(link_exe, settings_bstr, reserved) != S_OK) {
      AfxMessageBox(IDS_PROJ_ERROR);
      return;
    }

    count--;
  }
}


// Here we define one instance of the CMsDevWizardAppWiz class.  You can access
//  m_Dictionary and any other public members of this class through the
//  global MsDevWizardaw.
CMsDevWizardAppWiz MsDevWizardaw;

