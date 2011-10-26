///
///	@file stdcpp.cpp 
///	@brief Replacement routines for libstdc++. Used in libstdcpp.
///
///	This module provides replacement routines for libstdc++. AppWeb uses 
///	relies only minimally on the C++ runtime and so most of the overhead of 
///	libstdc++ is unnecessary.
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
#include	"mpr.h"

#if BLD_FEATURE_LIB_STDCPP && !WIN
////////////////////////////// Forward Declarations ////////////////////////////
#ifdef __cplusplus
extern "C" {
#endif

#if !BLD_FEATURE_MALLOC_HOOK
void *operator new(size_t size)
{
	void	*ptr;

	ptr = malloc(size);

	return ptr;
}

////////////////////////////////////////////////////////////////////////////////

void *operator new[](size_t size)
{
	void	*ptr;

	ptr = malloc(size);
	return ptr;
}

////////////////////////////////////////////////////////////////////////////////

void operator delete(void *ptr)
{
	free(ptr);
}

////////////////////////////////////////////////////////////////////////////////

void operator delete[](void *ptr)
{
	free(ptr);
}

#endif // !BLD_FEATURE_MALLOC_HOOK
////////////////////////////////////////////////////////////////////////////////
//
//	Do nothing when a pure virtual function is called
//

int __cxa_pure_virtual()
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
} // extern "C"
#endif

#else // BLD_FEATURE_LIB_STDCPP

static void dummyStdcpp() {}
#endif

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
