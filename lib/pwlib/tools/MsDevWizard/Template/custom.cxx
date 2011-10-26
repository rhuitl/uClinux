/*
 * custom.cxx
 *
 * PWLib application source file for $$PRODUCT_NAME$$
 *
 * Customisable application configurationfor OEMs.
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

#ifdef RC_INVOKED
#include <winver.h>
#else
#include <ptlib.h>
#include "custom.h"
#endif

#include "version.h"


////////////////////////////////////////////////////
//
// Variables required for PHTTPServiceProcess
//
////////////////////////////////////////////////////

#ifndef PRODUCT_NAME_TEXT
#define	PRODUCT_NAME_TEXT	"$$PRODUCT_NAME$$"
#endif

#ifndef EXE_NAME_TEXT
#define	EXE_NAME_TEXT	        "$$Root$$"
#endif

#ifndef MANUFACTURER_TEXT
#define	MANUFACTURER_TEXT	"$$MANUFACTURER$$"
#endif

#ifndef COPYRIGHT_HOLDER
#define	COPYRIGHT_HOLDER	"$$COPYRIGHT_HOLDER$$"
#endif

#ifndef GIF_NAME
#define GIF_NAME  		EXE_NAME_TEXT ".gif"
#define	GIF_WIDTH  300
#define GIF_HEIGHT 100
#endif

#ifndef EMAIL
#define	EMAIL NULL
#endif

#ifndef HOME_PAGE
#define	HOME_PAGE NULL
#endif

#ifndef PRODUCT_NAME_HTML
#define	PRODUCT_NAME_HTML PRODUCT_NAME_TEXT
#endif


$$IF(HAS_SIGNATURE)
#ifndef SIGNATURE_KEY
#define SIGNATURE_KEY     \
  $$SIGNATURE_KEY$$
#endif

$$ENDIF

#ifdef RC_INVOKED

#define AlphaCode alpha
#define BetaCode beta
#define ReleaseCode pl

#define MkStr2(s) #s
#define MkStr(s) MkStr2(s)

#if BUILD_NUMBER==0
#define VERSION_STRING \
    MkStr(MAJOR_VERSION) "." MkStr(MINOR_VERSION)
#else
#define VERSION_STRING \
    MkStr(MAJOR_VERSION) "." MkStr(MINOR_VERSION) MkStr(BUILD_TYPE) MkStr(BUILD_NUMBER)
#endif


VS_VERSION_INFO VERSIONINFO
#define alpha 1
#define beta 2
#define pl 3
  FILEVERSION     MAJOR_VERSION,MINOR_VERSION,BUILD_TYPE,BUILD_NUMBER
  PRODUCTVERSION  MAJOR_VERSION,MINOR_VERSION,BUILD_TYPE,BUILD_NUMBER
#undef alpha
#undef beta
#undef pl
  FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
#ifdef _DEBUG
  FILEFLAGS       VS_FF_DEBUG
#else
  FILEFLAGS       0
#endif
  FILEOS          VOS_NT_WINDOWS32
  FILETYPE        VFT_APP
  FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "0c0904b0"
        BEGIN
            VALUE "CompanyName",      MANUFACTURER_TEXT "\0"
            VALUE "FileDescription",  PRODUCT_NAME_TEXT "\0"
            VALUE "FileVersion",      VERSION_STRING "\0"
            VALUE "InternalName",     EXE_NAME_TEXT "\0"
            VALUE "LegalCopyright",   "Copyright © " COPYRIGHT_HOLDER " $$YEAR$$\0"
            VALUE "OriginalFilename", EXE_NAME_TEXT ".exe\0"
            VALUE "ProductName",      PRODUCT_NAME_TEXT "\0"
            VALUE "ProductVersion",   VERSION_STRING "\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0xc09, 1200
    END
END

#else

PHTTPServiceProcess::Info ProductInfo = {
    PRODUCT_NAME_TEXT,
    MANUFACTURER_TEXT,
    MAJOR_VERSION, MINOR_VERSION, PProcess::BUILD_TYPE, BUILD_NUMBER, __TIME__ __DATE__,

$$IF(HAS_SIGNATURE)
#include "$$Root$$.key"
    , NumSecuredKeys,

    {{ SIGNATURE_KEY }},
$$ELSE
    {{ 0 }}, { NULL }, 0, {{ 0 }},  // Only relevent for commercial apps
$$ENDIF

    HOME_PAGE,
    EMAIL,
    PRODUCT_NAME_HTML,
    NULL,  // GIF HTML, use calculated from below
    GIF_NAME,
    GIF_WIDTH,
    GIF_HEIGHT
};


#endif


// End of File ///////////////////////////////////////////////////////////////
