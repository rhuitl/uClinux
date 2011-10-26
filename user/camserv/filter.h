#ifndef FILTER_DOT_H
#define FILTER_DOT_H

#include "video.h"
#include "camconfig.h"

typedef struct filter_st Filter;

struct filter_st *filter_setup( CamConfig *ccfg, int *resarr );
void filter_destroy( Filter *filter_list );
void filter_list_deinit( Filter *filters );
void filter_list_init( Filter *filters, CamConfig *ccfg  );
void filter_list_process( Filter *filters, char *picture, 
			  char *final_picture_out,
			  const Video_Info *vinfo, Video_Info *out_vinfo );

typedef void *(*Filter_Init_Func)( CamConfig *ccfg, 
				   char *filter_section );
typedef void (*Filter_Deinit_Func)( void *filter_dat );
typedef void (*Filter_Func_Func)(char *in_data, char **out_data, void *cldat,
			    const Video_Info *vinfo_in, Video_Info *vinfo_out);

#endif
