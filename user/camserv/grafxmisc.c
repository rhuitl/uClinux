#include <stdio.h>
#include <stdlib.h>

#include "math.h"
#include "grafxmisc.h"

/*
 * camserv_get_pic_mean:  Calculate the mean value of the pixels in an image.
 *                      This routine is used for adjusting the values of
 *                      the pixels to reasonable brightness.
 *
 * Arguments:           width, height = Dimensions of the picture
 *                      buffer    = Buffer to picture.
 *                      is_rgb    = 1 if the picture is rgb, else 0
 *                      start{x,y}, end{x,y} = Region to calculate the
 *                                  mean of.  This MUST be valid before
 *                                  being passed in!
 *
 * Return values:       Returns the average of all the components if rgb, else
 *                      the average whiteness of each pixel if B&W
 */
int camserv_get_pic_mean( int width, int height, const unsigned char *buffer,
			  int is_rgb,int startx, int starty, int endx, 
			  int endy )
{
  double rtotal = 0, gtotal = 0, btotal = 0;
  int minrow, mincol, maxrow, maxcol, r, c;
  double bwtotal = 0, area;
  int rmean, gmean, bmean;
  const unsigned char *cp;
    
  minrow = starty;
  mincol = startx;
  maxrow = endy;
  maxcol = endx;

  area = (maxcol-mincol) * (maxrow-minrow);

  c = mincol;
  if( is_rgb ){
    for( r=minrow; r < maxrow; r++ ){
      cp = buffer + (r*width+c)*3;
      for( c=mincol; c < maxcol; c++ ) {
	rtotal += *cp++;
	gtotal += *cp++;
	btotal += *cp++;
      }
    }
    rmean = rtotal / area;
    gmean = gtotal / area;
    bmean = btotal / area;
    return (double)rmean * .299 +
	   (double)gmean * .587 +
           (double)bmean * .114;
  } else {
    for( r=minrow; r < maxrow; r++ ){
      cp = buffer + (r*width+c)*1;
      for( c=mincol; c < maxcol; c++ ) {
	bwtotal += *cp++;
      }
    }
    return (int)(bwtotal / area);
  }
}

/*
 * camserv_get_pic_stddev:  Calculate the standard deviation of the pixels in
 *                        a given picture.  
 *
 * Arguments:             width = Width of the picture (in pixels)
 *                        height = Height of the picture (in pixels)
 *                        buffer = Storage of the picture.
 *                        is_rgb = 1 if picture is RGBRGBRGBRGB, else 0
 *                        picmean = Average of the components of all the pixels
 *                                  in the buffer.
 *                   
 * Return values:         Returns the standard deviation from of the pixels
 *                        from the mean.
 */

int camserv_get_pic_stddev( int width, int height, const unsigned char *buffer,
			    int is_rgb, int picmean )
{
  const unsigned char *cp;
  int rtotal, gtotal, btotal, bwtotal;

  rtotal = gtotal = btotal = bwtotal = 0;
  
  if( !is_rgb ) {
    for( cp = buffer; cp < buffer + width * height; cp ++ ) 
      bwtotal += pow( (unsigned char ) *cp - picmean, 2 );
    bwtotal /= width * height;
    return sqrt( bwtotal );
  }

  for( cp = buffer; cp < buffer + width * height * 3; cp += 3 ) 
    bwtotal += pow((double) *(cp + 0) * .299 +
		   (double) *(cp + 1) * .587 +
		   (double) *(cp + 2) * .114 - picmean, 2 );
  bwtotal /= width * height;
  return sqrt(bwtotal);

#if 0
  /* This could be optimized a bit further, no? */
  for( cp = buffer; cp < buffer + width * height * 3; cp += 3 ){
    rtotal += pow((unsigned char) *(cp + 0) - picmean, 2);
    gtotal += pow((unsigned char) *(cp + 1) - picmean, 2);
    btotal += pow((unsigned char) *(cp + 2) - picmean, 2);
  }

  rtotal /= width * height;
  gtotal /= width * height;
  btotal /= width * height;

  /* Take each components percentage of the main color */
  return sqrt(rtotal) * .299 +
	 sqrt(gtotal) * .587 +
	 sqrt(btotal) * .114;
#if 0
  return (sqrt(rtotal) + sqrt(gtotal) + sqrt(btotal)) / 3;
#endif
#endif
}
