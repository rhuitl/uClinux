/*
 * RESOURCES.PRC
 *
 * PWLib application resources file for $$PRODUCT_NAME$$
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
 * $Log: resources.prc,v $
 * Revision 1.5  2002/11/09 02:29:20  robertj
 * Updated wizard to latest build flags and service program "pattern".
 *
 */

#include <pwlib/stdres.h>

#inline hdr
#include "main.h"
#inline end


String @IDS_TITLE              "$$PRODUCT_NAME$$";


MenuBar
{
    Class MainMenu;
    Window MainWindow;

    Menu PSTD_STR_FILE_MENU {
        Item {
            Title        PSTD_STR_NEW_MENU;
            Notify       NewCmd;
            Accelerators PSTD_STR_NEW_ACCEL;
            Id           @IDM_NEW;
        }
        Item {
            Title        PSTD_STR_OPEN_MENU;
            Notify       OpenCmd;
            Accelerators PSTD_STR_OPEN_ACCEL;
            Id           @IDM_OPEN;
        }
        Item {
            Title        PSTD_STR_CLOSE_MENU;
            Notify       CloseCmd;
            Accelerators PSTD_STR_CLOSE_ACCEL;
            Id           @IDM_CLOSE;
        }
        Separator;
        Item {
            Title        PSTD_STR_SAVE_MENU;
            Notify       SaveCmd;
            Accelerators PSTD_STR_SAVE_ACCEL;
            Id           @IDM_SAVE;
        }
        Item {
            Title        PSTD_STR_SAVE_AS_MENU;
            Notify       SaveAsCmd;
            Id           @IDM_SAVE_AS;
        }
        Separator;
        Item {
            Title        PSTD_STR_PRINT_MENU;
            Notify       PrintCmd;
            Accelerators PSTD_STR_PRINT_ACCEL;
            Id           @IDM_PRINT;
        }
        Item {
            Title        PSTD_STR_PRINTER_SETUP_MENU;
            Notify       PrinterSetupCmd;
        }
        Separator;
        Item {
            Title        PSTD_STR_EXIT_MENU;
            Notify       ExitCmd;
            Accelerators PSTD_STR_EXIT_ACCEL;
        }
    }

    Menu PSTD_STR_EDIT_MENU {
        Item {
            Title  PSTD_STR_UNDO_MENU;
            Notify "Undo";
            Accelerators { PSTD_STR_UNDO_ACCEL1,  PSTD_STR_UNDO_ACCEL2  }
        }
        Separator;
        Item {
            Title  PSTD_STR_CUT_MENU;
            Notify "Cut";
            Accelerators { PSTD_STR_CUT_ACCEL1,  PSTD_STR_CUT_ACCEL2  }
        }
        Item {
            Title  PSTD_STR_COPY_MENU;
            Notify "Copy";
            Accelerators { PSTD_STR_COPY_ACCEL1,  PSTD_STR_COPY_ACCEL2  }
        }
        Item {
            Title  PSTD_STR_PASTE_MENU;
            Notify "Paste";
            Accelerators { PSTD_STR_PASTE_ACCEL1, PSTD_STR_PASTE_ACCEL2 }
        }
        Item {
            Title  PSTD_STR_CLEAR_MENU;
            Notify "Clear";
            Accelerators { PSTD_STR_CLEAR_ACCEL1, PSTD_STR_CLEAR_ACCEL2 }
        }
        Separator;
        Item {
            Title        "&Select All";
            Notify       "SelectAll";
            Accelerators "Ctrl+Shift+A";
        }
    }
}


Icon @IDI_MAIN_WINDOW
{
    Dimensions 32,32,4;
    Colours {
          0,   0,   0,
        128,   0,   0,
          0, 128,   0,
        128, 128,   0,
          0,   0, 128,
        128,   0, 128,
          0, 128, 128,
        128, 128, 128,
        192, 192, 192,
        255,   0,   0,
          0, 255,   0,
        255, 255,   0,
          0,   0, 255,
        255,   0, 255,
          0, 255, 255,
        255, 255, 255
    }
    Pixels {
         0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
         0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
         0  0 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15  0  0 15 15 15 15 15 15 15  0  0 15 15 15  0 15 15 15 15  0  0  0  0  0 15 15 15  0  0
         0  0 15  0  0  0 15 15 15 15 15  0  0 15 15 15 15 15  0  0  0  0  9  9  0 10 10  0  0 15  0  0
         0  0 15 15  0  0  0 15 15 15  0  0 15 15 15 15 15  9 15 15  0  9  9  9  0 10 10 10  0 15  0  0
         0  0 15 15 15  0  0  0 15  0  0 15 15 15 15 15 15 15 15 15  0  9  9  9  0 10 10 10  0 15  0  0
         0  0 15 15 15 15  0  0  0  0 15 15 15 15 15 15 15  9 15 15  0  9  9  9  0 10 10 10  0 15  0  0
         0  0 15 15 15 15 15  0  0  0 15 15 15 15 15 15 15  0 15 15  0  9  0  0  0  0  0 10  0 15  0  0
         0  0 15 15 15 15  0  0  0  0  0 15 15 15 15 15 15 15  0  0  0  0 12 12  0 11 11  0  0 15  0  0
         0  0 15 15 15  0  0 15 15  0  0  0 15 15 15 15 15 12 15 12  0 12 12 12  0 11 11 11  0 15  0  0
         0  0 15 15  0  0 15 15 15 15  0  0  0 15 15 15 15 15 12 15  0 12 12 12  0 11 11 11  0 15  0  0
         0  0 15  0  0 15 15 15 15 15 15  0  0  0 15 15 15 12 15 12  0 12 12 12  0 11 11 11  0 15  0  0
         0  0 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0 12 15  0 12  0  0  0  0  0 11  0 15  0  0
         0  0 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0  0  0 15 15 15 15 15  0  0 15  0  0
         0  0 15 15 15 15 15 15 15  2  2  2 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 15 15 15 15 15  2  2  2 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 15 15 15 15 15  2 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 15 15  2  2  2  2  2  2  2  2 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 15 11 11 11 11 11 11 11 11 11 11 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 11 11 11 11 11 11 11 11 11 11 15 15 15 15 15  7  7  7  7  7  7  7  7  7  7 15 15  0  0
         0  0 15 11  9 11  9 11  9 11  9 11 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15  9 11  9 11  9 11  9 11 11 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15  9  9  9  9  9  9  9  9  9 15 15 15 15 15 15  7  7  7  7  7  7  7  7  7  7 15 15  0  0
         0  0 15  9  9  9  9  9  9  9  9  9  9 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 13 13 13 13 13 13 13 13 13 13 13 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 15 13 13 13 13 13 13 13 13 13 15 15 15 15 15  7  7  7  7  7  7  7  7  7  7 15 15  0  0
         0  0 15 15 15 12 12 12 12 12 12 12 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 15 15 15 12 12 12 12 12 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  0  0
         0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
         0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
    }
    AndMask {
        1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
        1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1
        1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
        1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
    }
    XorMask {
        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
        0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 0 0 1 1 1 1 1 1 1 0 0 1 1 1 0 1 1 1 1 0 0 0 0 0 1 1 1 0 0
        0 0 1 0 0 0 1 1 1 1 1 0 0 1 1 1 1 1 0 0 0 0 1 1 0 1 1 0 0 1 0 0
        0 0 1 1 0 0 0 1 1 1 0 0 1 1 1 1 1 1 1 1 0 1 1 1 0 1 1 1 0 1 0 0
        0 0 1 1 1 0 0 0 1 0 0 1 1 1 1 1 1 1 1 1 0 1 1 1 0 1 1 1 0 1 0 0
        0 0 1 1 1 1 0 0 0 0 1 1 1 1 1 1 1 1 1 1 0 1 1 1 0 1 1 1 0 1 0 0
        0 0 1 1 1 1 1 0 0 0 1 1 1 1 1 1 1 0 1 1 0 1 0 0 0 0 0 1 0 1 0 0
        0 0 1 1 1 1 0 0 0 0 0 1 1 1 1 1 1 1 0 0 0 0 1 1 0 1 1 0 0 1 0 0
        0 0 1 1 1 0 0 1 1 0 0 0 1 1 1 1 1 1 1 1 0 1 1 1 0 1 1 1 0 1 0 0
        0 0 1 1 0 0 1 1 1 1 0 0 0 1 1 1 1 1 1 1 0 1 1 1 0 1 1 1 0 1 0 0
        0 0 1 0 0 1 1 1 1 1 1 0 0 0 1 1 1 1 1 1 0 1 1 1 0 1 1 1 0 1 0 0
        0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 1 1 0 1 0 0 0 0 0 1 0 1 0 0
        0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 1 1 1 1 1 0 0 1 0 0
        0 0 1 1 1 1 1 1 1 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 1 1 1 1 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 1 1 1 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 1 1 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 1 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 0 0 0 0 0 0 0 0 0 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 1 1 0 0
        0 0 1 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 1 1 0 0
        0 0 1 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 0 0 0 0 0 0 0 0 0 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 1 1 0 0
        0 0 1 1 1 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 1 1 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0
        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
        0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    }
}


ModalDialog {
    Title "About $$PRODUCT_NAME$$";
    Dim   165, 135;
    Id    @IDD_ABOUT;

    CentreText { Title "$$PRODUCT_NAME$$";	      Pos 30, 10;  Dim 125,  8; }
    CentreText { Title "Version 1.0a1";               Pos 30, 20;  Dim 125,  8; }
    CentreText { Title "by $$MANUFACTURER$$           Pos 30, 30;  Dim 125,  8; }

    StaticIcon { Icon IDI_MAIN_WINDOW;                Pos 10, 10; }

    StaticBox  {                                      Pos  5, 75;  Dim 150, 1; }

    CentreText { Title "This software is free to all personal users.";
                                                      Pos  5, 45;  Dim 150, 10; }
    CentreText { Title "All other users should contact the author for licensing details.";
                                                      Pos 10, 55;  Dim 140, 20; }

    StaticBox  {                                      Pos  5, 40;  Dim 150, 1; }

    CentreText { Title "Copyright © $$YEAR$$ $$COPYRIGHT_HOLDER$$"; Pos  5, 80;  Dim 150, 9; }

    StaticBox  {                                      Pos  5, 100; Dim 150, 1; }

    PushButton { Title "Ok";  Options ok, default;    Pos 55, 110; Dim 45, 15; }
}


///////////////////////////////////////////////////////////////////////////////
