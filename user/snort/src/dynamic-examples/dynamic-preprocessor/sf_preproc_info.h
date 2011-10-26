/*
 * sf_preproc_info.h
 *
 * Copyright (C) 2006 Sourcefire,Inc
 * Steven A. Sturges <ssturges@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Description:
 *
 * This file is part of an example of a dynamically loadable preprocessor.
 *
 * NOTES:
 *
 */
#ifndef SF_PREPROC_INFO_H_
#define SF_PREPROC_INFO_H_

#define MAJOR_VERSION   1
#define MINOR_VERSION   0
#define BUILD_VERSION   1
#define PREPROC_NAME    "SF_Dynamic_Example_Preprocessor"

#define DYNAMIC_PREPROC_SETUP   ExampleSetup
extern void ExampleSetup();

#endif /* SF_PREPROC_INFO_H_ */

