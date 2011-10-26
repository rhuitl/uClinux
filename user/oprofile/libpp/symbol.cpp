/**
 * @file symbol.cpp
 * Symbol containers
 *
 * @remark Copyright 2002, 2004 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Philippe Elie
 * @author John Levon
 */


#include "symbol.h"
#include <iostream>

using std::cerr;
using std::endl;

column_flags symbol_entry::output_hint(column_flags fl) const
{
	if (app_name != image_name)
		fl = column_flags(fl | cf_image_name);

	// FIXME: see comment in symbol.h: why we don't use sample.vma + size ?
	if (sample.vma & ~0xffffffffLLU)
		fl = column_flags(fl | cf_64bit_vma);

	return fl;
}
