/*
 * detection_lib_meta.h
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
#ifndef _DETECTION_LIB_META_H_
#define _DETECTION_LIB_META_H_

/* Version for this rule library */
#define DETECTION_LIB_MAJOR 1
#define DETECTION_LIB_MINOR 0
#define DETECTION_LIB_BUILD 1
#define DETECTION_LIB_NAME "Snort_Dynamic_Rule_Example"

/* Required version and name of the engine */
#define REQ_ENGINE_LIB_MAJOR 1
#define REQ_ENGINE_LIB_MINOR 0
#define REQ_ENGINE_LIB_NAME "SF_SNORT_DETECTION_ENGINE"

#endif /* _DETECTION_LIB_META_H_ */
