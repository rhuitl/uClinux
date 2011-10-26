/*
 * main.h
 *
 * PWLib application header file for $$PRODUCT_NAME$$
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

#ifndef _$$APP_CLASS_NAME$$_MAIN_H
#define _$$APP_CLASS_NAME$$_MAIN_H


$$IF(IS_SERVICE)
$$IF(HAS_HTTP)
#include <ptclib/httpsvc.h>
$$ELSE
#include <ptlib/svcproc.h>
$$ENDIF
$$ENDIF

$$IF(IS_GUI)
class MainWindow : public $$PARENT_WIN_CLASS$$
{
  PCLASSINFO(MainWindow, $$PARENT_WIN_CLASS$$)
  
  public:
    MainWindow(PArgList & args);

    PDECLARE_NOTIFIER(PMenuItem, MainWindow, NewCmd);
    PDECLARE_NOTIFIER(PMenuItem, MainWindow, OpenCmd);
    PDECLARE_NOTIFIER(PMenuItem, MainWindow, CloseCmd);
    PDECLARE_NOTIFIER(PMenuItem, MainWindow, SaveCmd);
    PDECLARE_NOTIFIER(PMenuItem, MainWindow, SaveAsCmd);
    PDECLARE_NOTIFIER(PMenuItem, MainWindow, PrintCmd);
    PDECLARE_NOTIFIER(PMenuItem, MainWindow, PrinterSetupCmd);
    PDECLARE_NOTIFIER(PMenuItem, MainWindow, ExitCmd);

    PDECLARE_COMMAND_ENABLE("Copy", MainWindow, CopyCmd, CanCopy);
    PDECLARE_COMMAND_ENABLE("Copy", MainWindow, PasteCmd, CanPaste);

  private:
    PPrintInfo printInfo;
};

$$ENDIF

class $$APP_CLASS_NAME$$ : public $$PARENT_APP_CLASS$$
{
  PCLASSINFO($$APP_CLASS_NAME$$, $$PARENT_APP_CLASS$$)

  public:
    $$APP_CLASS_NAME$$();
    virtual void Main();
$$IF(IS_SERVICE)
    virtual BOOL OnStart();
    virtual void OnStop();
    virtual void OnControl();
$$IF(HAS_HTTP)
    virtual void OnConfigChanged();
$$IF(HAS_SIGNATURE)
    virtual void AddUnregisteredText(PHTML & html);
$$ENDIF
    virtual BOOL Initialise(const char * initMsg);
$$ENDIF
$$ENDIF
};


#endif  // _$$APP_CLASS_NAME$$_MAIN_H


// End of File ///////////////////////////////////////////////////////////////
