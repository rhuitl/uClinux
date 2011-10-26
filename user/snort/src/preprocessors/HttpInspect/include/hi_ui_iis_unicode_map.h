/**
**  @file       hi_ui_iis_unicode_map.h
**  
**  @author     Daniel Roelker <droelker@sourcefire.com>
**  
**  @brief      Header file for hi_ui_iis_unicode_map functions.
*/
#ifndef __HI_UI_IIS_UNICODE_H__
#define __HI_UI_IIS_UNICODE_H__

#include "hi_include.h"
#include "hi_ui_config.h"

/**
**  This is the define for the iis_unicode_map array when there is no
**  ASCII mapping.
*/
#define HI_UI_NON_ASCII_CODEPOINT -1

int hi_ui_parse_iis_unicode_map(int **iis_unicode_map, char *filename,
                                int iCodePage);

#endif
