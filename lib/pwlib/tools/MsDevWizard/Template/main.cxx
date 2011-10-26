/*
 * main.cxx
 *
 * PWLib application source file for $$PRODUCT_NAME$$
 *
 * Main program entry point.
 *
 * Copyright (c) $$YEAR$$ $$COPYRIGHT_HOLDER$$
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
 * $Log$
 */

#include "precompile.h"
#include "main.h"
$$IF(IS_GUI)
#include "resources.h"
$$ENDIF
$$IF(HAS_HTTP)
#include "custom.h"
$$ELSE
#include "version.h"
$$ENDIF


PCREATE_PROCESS($$APP_CLASS_NAME$$);

$$IF(HAS_HTTP)

const WORD DefaultHTTPPort = 6666;
static const char UsernameKey[] = "Username";
static const char PasswordKey[] = "Password";
static const char LogLevelKey[] = "Log Level";
static const char HttpPortKey[] = "HTTP Port";
$$ENDIF


$$APP_CLASS_NAME$$::$$APP_CLASS_NAME$$()
$$IF(HAS_HTTP)
  : $$PARENT_APP_CLASS$$(ProductInfo)
$$ELSE
  : $$PARENT_APP_CLASS$$("$$MANUFACTURER$$", "$$PRODUCT_NAME$$", MAJOR_VERSION, MINOR_VERSION, BUILD_TYPE, BUILD_NUMBER)
$$ENDIF
{
}

$$IF(IS_SERVICE)

BOOL $$APP_CLASS_NAME$$::OnStart()
{
  // change to the default directory to the one containing the executable
  PDirectory exeDir = GetFile().GetDirectory();

#if defined(_WIN32) && defined(_DEBUG)
  // Special check to aid in using DevStudio for debugging.
  if (exeDir.Find("\\Debug\\") != P_MAX_INDEX)
    exeDir = exeDir.GetParent();
#endif
  exeDir.Change();

$$IF(HAS_HTTP)
  httpNameSpace.AddResource(new PHTTPDirectory("data", "data"));
  httpNameSpace.AddResource(new PServiceHTTPDirectory("html", "html"));

  return $$PARENT_APP_CLASS$$::OnStart();
$$ELSE
  return TRUE;
$$ENDIF
}


void $$APP_CLASS_NAME$$::OnStop()
{
  $$PARENT_APP_CLASS$$::OnStop();
}


void $$APP_CLASS_NAME$$::OnControl()
{
}

$$IF(HAS_HTTP)

void $$APP_CLASS_NAME$$::OnConfigChanged()
{
}

$$IF(HAS_SIGNATURE)

void $$APP_CLASS_NAME$$::AddUnregisteredText(PHTML &)
{
}
$$ENDIF


BOOL $$APP_CLASS_NAME$$::Initialise(const char * initMsg)
{
  PConfig cfg("Parameters");

  // Sert log level as early as possible
  SetLogLevel((PSystemLog::Level)cfg.GetInteger(LogLevelKey, GetLogLevel()));
#if PTRACING
  if (GetLogLevel() >= PSystemLog::Warning)
    PTrace::SetLevel(GetLogLevel()-PSystemLog::Warning);
  else
    PTrace::SetLevel(0);
  PTrace::ClearOptions(PTrace::Timestamp);
  PTrace::SetOptions(PTrace::DateAndTime);
#endif

  // Get the HTTP basic authentication info
  PString username = cfg.GetString(UsernameKey);
  PString password = PHTTPPasswordField::Decrypt(cfg.GetString(PasswordKey));

  PHTTPSimpleAuth authority(GetName(), username, password);

  // Create the parameters URL page, and start adding fields to it
  PConfigPage * rsrc = new PConfigPage(*this, "Parameters", "Parameters", authority);

  // HTTP authentication username/password
  rsrc->Add(new PHTTPStringField(UsernameKey, 25, username));
  rsrc->Add(new PHTTPPasswordField(PasswordKey, 25, password));

  // Log level for messages
  rsrc->Add(new PHTTPIntegerField(LogLevelKey,
                                  PSystemLog::Fatal, PSystemLog::NumLogLevels-1,
                                  GetLogLevel(),
                                  "1=Fatal only, 2=Errors, 3=Warnings, 4=Info, 5=Debug"));

  // HTTP Port number to use.
  WORD httpPort = (WORD)cfg.GetInteger(HttpPortKey, DefaultHTTPPort);
  rsrc->Add(new PHTTPIntegerField(HttpPortKey, 1, 32767, httpPort));

  // Finished the resource to add, generate HTML for it and add to name space
  PServiceHTML html("System Parameters");
  rsrc->BuildHTML(html);
  httpNameSpace.AddResource(rsrc, PHTTPSpace::Overwrite);


  // Create the home page
  static const char welcomeHtml[] = "welcome.html";
  if (PFile::Exists(welcomeHtml))
    httpNameSpace.AddResource(new PServiceHTTPFile(welcomeHtml, TRUE), PHTTPSpace::Overwrite);
  else {
    PHTML html;
    html << PHTML::Title("Welcome to " + GetName())
         << PHTML::Body()
         << GetPageGraphic()
         << PHTML::Paragraph() << "<center>"

         << PHTML::HotLink("Parameters") << "Parameters" << PHTML::HotLink()
         << PHTML::Paragraph();

    if (!systemLogFileName && systemLogFileName != "-")
      html << PHTML::HotLink("logfile.txt") << "Full Log File" << PHTML::HotLink()
           << PHTML::BreakLine()
           << PHTML::HotLink("tail_logfile") << "Tail Log File" << PHTML::HotLink()
           << PHTML::Paragraph();
 
    html << PHTML::HRule()
         << GetCopyrightText()
         << PHTML::Body();
    httpNameSpace.AddResource(new PServiceHTTPString("welcome.html", html), PHTTPSpace::Overwrite);
  }

  // set up the HTTP port for listening & start the first HTTP thread
  if (ListenForHTTP(httpPort))
    PSYSTEMLOG(Info, "Opened master socket for HTTP: " << httpListeningSocket->GetPort());
  else {
    PSYSTEMLOG(Fatal, "Cannot run without HTTP port: " << httpListeningSocket->GetErrorText());
    return FALSE;
  }

  PSYSTEMLOG(Info, "Service " << GetName() << ' ' << initMsg);
  return TRUE;
}

$$ENDIF
$$ENDIF

void $$APP_CLASS_NAME$$::Main()
{
$$IF(HAS_HTTP)
  Suspend();
$$ELSE
$$IF(IS_GUI)
  SetAboutDialogID(IDD_ABOUT);

  PNEW MainWindow(GetArguments());

  PApplication::Main();
$$ELSE
  PArgList & args = GetArguments();
$$ENDIF
$$ENDIF
}

$$IF(IS_GUI)

MainWindow::MainWindow(PArgList & /*args*/)
{
  SetTitle(PResourceString(IDS_TITLE));
  SetIcon(PIcon(IDI_MAIN_WINDOW));
  SetMenu(new MainMenu(this));

  UpdateCommandSources();
  ShowAll();
}


void MainWindow::NewCmd(PMenuItem &, INT)
{
  // New document
}


void MainWindow::OpenCmd(PMenuItem &, INT)
{
  POpenFileDialog dlg(this);
  if (dlg.RunModal()) {
    // Open existing document
  }
}


void MainWindow::CloseCmd(PMenuItem &, INT)
{
  // Close document
}


void MainWindow::SaveCmd(PMenuItem &, INT)
{
  // Save current document
}


void MainWindow::SaveAsCmd(PMenuItem &, INT)
{
  PSaveFileDialog dlg(this);
  if (dlg.RunModal()) {
    // Save document to new name
  }
}


void MainWindow::PrintCmd(PMenuItem &, INT)
{
  PPrintJobDialog dlg(this, printInfo);
  if (dlg.RunModal()) {
    printInfo = dlg.GetPrintInfo();
    PPrintCanvas canvas("$$PRODUCT_NAME$$", printInfo);

    // Add printing code here
  }
}


void MainWindow::PrinterSetupCmd(PMenuItem &, INT)
{
  PPrinterSetupDialog dlg(this, printInfo);
  if (dlg.RunModal())
    printInfo = dlg.GetPrintInfo();
}


void MainWindow::ExitCmd(PMenuItem &, INT)
  // The Exit menu ... well ... exits.
{
  owner->Terminate();
}


void MainWindow::CopyCmd()
{
  PClipboard clip(this);
  // Do something with the clipboard
}


BOOL MainWindow::CanCopy()
{
  // If want copy menu enabled
  return TRUE;
}


void MainWindow::PasteCmd()
{
  PClipboard clip(this);
  // Do something with the clipboard
}


BOOL MainWindow::CanPaste()
{
  // If want paste menu enabled, ie clipboard has right format
  return TRUE;
}

$$ENDIF

// End of File ///////////////////////////////////////////////////////////////
