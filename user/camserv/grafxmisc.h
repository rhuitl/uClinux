#ifndef GRAFXMISC_DOT_H
#define GRAFXMISC_DOT_H

int camserv_get_pic_mean( int width, int height, const unsigned char *buffer,
			  int is_rgb, int startx, int starty, int endx,
			  int endy );
int camserv_get_pic_stddev( int width, int height, const unsigned char *buffer,
			    int is_rgb, int picmean );

static int clip_to(int x, int low, int high){
  if(x<low) 
      return low;
  else if (x>high) 
      return high;
  else 
      return x;
}

#endif
