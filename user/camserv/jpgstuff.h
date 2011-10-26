#ifndef JPGSTUFF_DOT_H
#define JPGSTUFF_DOT_H

#include <setjmp.h>

#include <jpeglib.h>
#include <jerror.h>

typedef struct jpeg_wrapper_st {
  struct jpeg_error_mgr err_mgr;
  struct jpeg_compress_struct cinfo;
  struct jpeg_destination_mgr dest_mgr;

  int jpeg_quality;
  jmp_buf setjmp_buffer;  
  
  JOCTET *jpeg_output_buffer;
  int user_specd_buffer;

  size_t jpeg_buffer_size;
  size_t actual_jpeg_size;
  int is_black_white;
  int magic_fairy_dust;
} JPEG_Wrapper;


typedef struct jpeg_param_list_st {
  int quality;
  int width;
  int height;
  int is_black_white;
} JPEG_Params;


extern int JPEG_Wrapper_initialize( JPEG_Wrapper *jwrap, 
				    const JPEG_Params *jparams,
				    char *output_buffer, int outbuf_size );
extern void JPEG_Wrapper_deinitialize( JPEG_Wrapper *jwrap );
extern void JPEG_Wrapper_do_compress( JPEG_Wrapper *jwrap, 
				      unsigned int width, unsigned int height,
				      JSAMPLE *image_data );



#endif
