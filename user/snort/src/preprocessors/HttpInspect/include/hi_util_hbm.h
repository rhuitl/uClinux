/**
**  @file           hi_hbm.h
**  
**  @author         Marc Norton <mnorton@sourcefire.com>
**  
**  @brief          Header file for Horspool type Boyer-Moore implementation
*/
#ifndef __HI_HBM_H__
#define __HI_HBM_H__

typedef struct {

 unsigned char *P;
 int            M;
 short          bcShift[256];

}HBM_STRUCT;

HBM_STRUCT * hbm_prep(unsigned char * pat, int m);
unsigned char * hbm_match(HBM_STRUCT * px, unsigned char *text, int n);

#endif
