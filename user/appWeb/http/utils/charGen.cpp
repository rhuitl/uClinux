///
///	@file 	charGen.cpp
/// @brief 	Generate the character lookup tables for escape / descape routines
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	The latest version of this code is available at http://www.mbedthis.com
//
//	This software is open source; you can redistribute it and/or modify it 
//	under the terms of the GNU General Public License as published by the 
//	Free Software Foundation; either version 2 of the License, or (at your 
//	option) any later version.
//
//	This program is distributed WITHOUT ANY WARRANTY; without even the 
//	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
//	See the GNU General Public License for more details at:
//	http://www.mbedthis.com/downloads/gplLicense.html
//	
//	This General Public License does NOT permit incorporating this software 
//	into proprietary programs. If you are unable to comply with the GPL, a 
//	commercial license for this software and support services are available
//	from Mbedthis Software at http://www.mbedthis.com
//
/////////////////////////////////// Includes ///////////////////////////////////

#include	"http/http.h"

//////////////////////////////////// Code //////////////////////////////////////

int main(int argc, char *argv[])
{
    uchar	 flags;
    uint	 c;

	mprPrintf("static uchar charMatch[256] = {\n\t 0,");

    for (c = 1; c < 256; ++c) {
		flags = 0;
		if (c % 16 == 0)
			mprPrintf("\n\t");
#if WIN
		if (strchr("&;`'\"|*?~<>^()[]{}$\\\n\r%", c)) {
			flags |= MPR_HTTP_ESCAPE_SHELL;
		}
#else
		if (strchr("&;`'\"|*?~<>^()[]{}$\\\n", c)) {
			flags |= MPR_HTTP_ESCAPE_SHELL;
		}
#endif
		//
		//	Unsafe chars in URLs are: 
		//		0x00-0x1F, 0x7F, 0x80-0xFF, <>'"#%{}|\^~[]
		//		Space, \t, \r, \n
		//	Reserved chars with special meaning are:
		//		;/?: @=&		FUTURE -- should ";?" be in the list
		//
		if (!isalnum(c) && !strchr("$-_.+!*'(),:@&=/~", c)) {
			flags |= MPR_HTTP_ESCAPE_PATH;
		}

		if (strchr("<>&()#", c) != 0) {
			flags |= MPR_HTTP_ESCAPE_HTML;
		}
		mprPrintf("%2u%c", flags, (c < 255) ? ',' : ' ');

    }
    mprPrintf("\n};\n");
    return 0;
}

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
