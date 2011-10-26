/****************************************************************************
 * RRDtool 1.2.10  Copyright by Tobi Oetiker, 1997-2005
 ****************************************************************************
 * rrd_gfx_tiny_svg.c  tiny graphics replacement to produce svg
 *                 requiring no externel libs and minimal size
 *                 Copyright (C) 2009 Ken Wilson ken.wilson@mcaffe.com>
  **************************************************************************/

/* #define DEBUG */

#ifdef DEBUG
# define DPRINTF(a...)  fprintf(stderr, a);
#else
# define DPRINTF(a...)
#endif

#include "rrd_tool.h"
#include "rrd_gfx.h"

#ifdef ENABLE_SVG_TINY
#include "rrd_afm.h"
#include "unused.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asm/byteorder.h>

/* SVG primitives */

static void doPreamble(FILE *fp, int height, int width) {
  fprintf(fp, "<?xml version=\"1.0\" standalone=\"no\"?>\n <!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\"\n \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n<svg width=\"%d\" height=\"%d\" version=\"1.1\"\n xmlns=\"http://www.w3.org/2000/svg\">\n", width, height); 
}

static void finishDocument(FILE *fp) {
  fprintf(fp, "</svg>\n");
}

static void
drawline(FILE *fp, int x1, int y1, int x2, int y2, int c, int don, int dof)
{
  fprintf(fp, "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" " \
   "style=\"stroke:rgb(%d,%d,%d);stroke-dasharray:%d,%d\"/>\n", x1, y1, x2, y2, (c >> 24) & 0xFF, (c >> 16) & 0xFF, (c >> 8) &0xFF, don, dof); 
}

static void 
drawpoly(FILE *fp,
        int num_points,
        int *xpoints,
        int *ypoints,
        int st_color,
        int filled,
        int fill_color,
        int don,
        int dof
        )
{
  int i;
  fprintf(fp, "<polygon points=\"");
  for (i = 0; i < num_points; i++) {
    fprintf(fp, "%d,%d ", xpoints[i], ypoints[i]);
  }
  fprintf(fp, "\"\n style=\"");
  if (filled) {
    fprintf(fp, "fill:rgb(%d,%d,%d);\n", (fill_color >> 24) & 0xFF, (fill_color >> 16) & 0xFF, (st_color >> 8) &0xFF);
  }
  fprintf(fp, "stroke:rgb(%d,%d,%d);stroke-dasharray:%d,%d\"/>\n", (st_color >> 24) & 0xFF, (st_color >> 16) & 0xFF, (st_color >> 8) &0xFF, don, dof); 
}

double
gfx_get_text_width(
    gfx_canvas_t *canvas,
    double start,
	char *font,
	double size,
    double tabwidth,
	char *text,
	int rotation)
{
	char *tp;
	int n = 0;

	switch ((int) rotation) {
	case 270: return 10;
	}

	for (tp = text; *tp; tp++) {
		switch (*tp) {
		case '\t':
		    n += (10 * tabwidth);
			break;
        case ' ':
          /* multiple spaces will coalesce into 1 */
          //while (*tp && (*tp == ' ')) tp++;
		default:
			n += 10;
			break;
		}
	}
	return n;
}

double
gfx_get_text_height(
    gfx_canvas_t *canvas,
    double start,
	char *font,
	double size,
    double tabwidth,
	char *text,
	int rotation)
{
	char *tp;
	int n = 0;

	switch ((int) rotation) {
	case 270:
	  return 10; 
	break;
	}

	for (tp = text; *tp; tp++) {
		switch (*tp) {
		case '\t':
		    n += (10 * tabwidth);
			break;
        case ' ':
            /* multiple spaces will coalesce into 1 */
            //while (*tp && (*tp == ' ')) tp++;
		default:
			n += 10;
			break;
		}
	}
	return n;
}

gfx_canvas_t *
gfx_new_canvas(void)
 {
    gfx_canvas_t *canvas = calloc(1, sizeof(gfx_canvas_t));
    canvas->firstnode = NULL;
    canvas->lastnode = NULL;
    canvas->imgformat = IF_PNG;
    canvas->interlaced = 0;
    canvas->zoom = 1.0;
    canvas->font_aa_threshold = -1.0;
    canvas->aa_type = AA_NORMAL;
    return canvas;
}

int
gfx_destroy(gfx_canvas_t *canvas)
{  
  gfx_node_t *next,*node = canvas->firstnode;
  while(node){
    next = node->next;
    free(node->path);
    free(node->text);
    free(node->filename);
    free(node);
    node = next;
  }
  free(canvas);
  return 0;
}

static gfx_node_t *
gfx_new_node(gfx_canvas_t *canvas, enum gfx_en type)
{
  gfx_node_t *node = calloc(1, sizeof(gfx_node_t));
  if (node == NULL) return NULL;
  node->type = type;
  node->color = 0x0;     /* color of element  0xRRGGBBAA  alpha 0xff is solid*/
  node->size = 0.0;       /* font size, line width */
  node->path = NULL;     /* path */
  node->points = 0;
  node->points_max = 0;
  node->closed_path = 0;
  node->filename = NULL; /* font or image filename */
  node->text = NULL;
  node->x = 0.0;
  node->y = 0.0;         /* position */
  node->angle = 0;  
  node->halign = GFX_H_NULL; /* text alignement */
  node->valign = GFX_V_NULL; /* text alignement */
  node->tabwidth = 0.0; 
  node->next = NULL; 
  if (canvas->lastnode != NULL){
      canvas->lastnode->next = node;
  }
  if (canvas->firstnode == NULL){
      canvas->firstnode = node;
  }  
  canvas->lastnode = node;
  return node;
}



gfx_node_t *
gfx_new_text(
	gfx_canvas_t *canvas,
	double x,
	double y,
	gfx_color_t color,
	char *font,
	double size,
	double tabwidth,
	double angle,
	enum gfx_h_align_en h_align,
	enum gfx_v_align_en v_align,
	char* text)
{
   gfx_node_t *node = gfx_new_node(canvas, GFX_TEXT);
   
   node->text = strdup(text);
   node->size = size;
   node->filename = strdup(font);
   node->x = x;
   node->y = y;
   node->angle = angle;   
   node->color = color;
   node->tabwidth = tabwidth;
   node->halign = h_align;
   node->valign = v_align;
   return node;
}

gfx_node_t *
gfx_new_line(
	gfx_canvas_t *canvas,
	double X0, double Y0, 
	double X1, double Y1,
 	double width, gfx_color_t color)
{
  return gfx_new_dashed_line(canvas, X0, Y0, X1, Y1, width, color, 0, 0);
}

gfx_node_t *
gfx_new_dashed_line(
	gfx_canvas_t *canvas,
	double X0, double Y0,
	double X1, double Y1,
	double width, gfx_color_t color,
	double dash_on, double dash_off)
{
  ArtVpath *vec;
  gfx_node_t *node = gfx_new_node(canvas, GFX_LINE);
  if (node == NULL) return NULL;

  vec = calloc(3, sizeof(ArtVpath));
  if (vec == NULL) return NULL;

  vec[0].code = ART_MOVETO_OPEN;
  vec[0].x = X0;
  vec[0].y = Y0;
  vec[1].code = ART_LINETO;
  vec[1].x = X1;
  vec[1].y = Y1;
  vec[2].code = ART_END;
  vec[2].x = 0;
  vec[2].y = 0;
  
  node->points = 3;
  node->points_max = 3;
  node->color = color;
  node->size  = width;
  node->dash_on = dash_on;
  node->dash_off = dash_off;
  node->path  = vec;
  return node;
}

gfx_node_t *
gfx_new_area(
	gfx_canvas_t *canvas, 
	double X0, double Y0,
	double X1, double Y1,
	double X2, double Y2,
	gfx_color_t color)
{
  ArtVpath *vec;
  gfx_node_t *node = gfx_new_node(canvas, GFX_AREA);
  if (node == NULL) return NULL;

  vec = calloc(5, sizeof(ArtVpath));
  if (vec == NULL) return NULL;

  vec[0].code = ART_MOVETO;
  vec[0].x = X0;
  vec[0].y = Y0;
  vec[1].code = ART_LINETO;
  vec[1].x = X1;
  vec[1].y = Y1;
  vec[2].code = ART_LINETO;
  vec[2].x = X2;
  vec[2].y = Y2;
  vec[3].code = ART_LINETO;
  vec[3].x = X0;
  vec[3].y = Y0;
  vec[4].code = ART_END;
  vec[4].x = 0;
  vec[4].y = 0;
  
  node->points = 5;
  node->points_max = 5;
  node->color = color;
  node->path  = vec;

  return node;
}

/* add a point to a line or to an area */
int
gfx_add_point(gfx_node_t *node, double x, double y)
{
  if (node == NULL) return 1;

  if (node->type == GFX_AREA) {
    double X0 = node->path[0].x;
    double Y0 = node->path[0].y;
	ArtVpath *vec = art_new(ArtVpath, node->points_max + 1);
    node->points -= 2;
	memcpy(vec, node->path, sizeof(ArtVpath) * node->points_max);
	art_free(node->path);
	node->path = vec;
	node->points_max++;
	node->path[node->points].code = ART_LINETO;
	node->path[node->points].x = x;
	node->path[node->points++].y = y;
	node->path[node->points].code = ART_LINETO;
	node->path[node->points].x = X0;
	node->path[node->points++].y = Y0;
	node->path[node->points].code = ART_END;
	node->path[node->points].x = 0;
	node->path[node->points++].y = 0;
  } else if (node->type == GFX_LINE) {
	ArtVpath *vec = art_new(ArtVpath, node->points_max + 1);
    node->points -= 1;
	memcpy(vec, node->path, sizeof(ArtVpath) * node->points_max);
	art_free(node->path);
	node->path = vec;
	node->points_max++;
	node->path[node->points].code = ART_LINETO;
	node->path[node->points].x = x;
	node->path[node->points++].y = y;
	node->path[node->points].code = ART_END;
	node->path[node->points].x = 0;
	node->path[node->points++].y = 0;
  } else {
    /* can only add point to areas and lines */
    return 1;
  }
  return 0;
}

void
gfx_close_path(gfx_node_t *node)
{
	node->closed_path = 1;
    if (node->path[0].code == ART_MOVETO_OPEN)
		node->path[0].code = ART_MOVETO;
}


static void
drawtext(FILE *fp, char *s, int x, int y, int c, int angle, int halign, int valign)
{
    const char *text_center = "middle";
    const char *text_left_justify = "start";
    const char *text_right_justify = "end";
    
    const char *text_top_align = "baseline";
    const char *text_normal_align = "baseline";
    const char *text_bottom_align = "-50%";
    
    const char *halign_str = text_center;
    const char *valign_str = text_bottom_align;
    int i = 0;
    int numspaces = 0;
    
    switch (halign) {
      case GFX_H_RIGHT:
        halign_str = text_right_justify;
      break;
      case GFX_H_CENTER:
        halign_str = text_center;
      break;
      case GFX_H_LEFT:
        halign_str = text_left_justify;
      break;
    }
    
    switch (valign) {
      case GFX_V_TOP:
      y +=8;
      break;
      case GFX_V_CENTER:
      break;
      case GFX_V_BOTTOM:
      break;
    }
    
    /* SVG ignores leading spaces, so we should do any offsets manually */
    while (*(s + i) && ((*s + i) == ' ' || (*s + i) == '\t')) {
      i++;
      numspaces++;
    }
    
    /* Only do this for left justified text, as the absolute positioning of the start matters more here */
    if (halign_str == text_left_justify) {
      if (angle == 0) {
        x += 15 * numspaces;
      } else if (angle == 270) {
        y += 15 * numspaces;
      } 
    }
     
    fprintf(fp, "<text x=\"%d\" y=\"%d\" font-family=\"Verdana\" font-size=\"10\" rotate=\"%d\" fill=\"#%x%x%x\" text-anchor=\"%s\">\n",
    x, y, angle, (c >> 24) & 0xFF, (c >> 16) & 0xFF, (c >> 8) & 0xFF, halign_str);
   
    for (i = 0; *(s + i); i++) {
      switch (*(s + i)) {
      case '<':
        fputs("&lt;", fp);
        break;
      case '>':
        fputs("&gt;", fp);
        break;
      default:
        fputc(*(s + i), fp);
      }  
    }
    fprintf(fp, "\n</text>\n"); 
}

int
gfx_render(
	gfx_canvas_t *canvas,
	art_u32 height,
	art_u32 width,
	gfx_color_t background,
	FILE *fp)
{
    gfx_node_t *node = canvas->firstnode;    
    int i, j;
    
    doPreamble(fp, width, height);    
    while (node) {
        switch (node->type) {
        case GFX_AREA: {
		const int npm1 = node->points - 1;
		int pathx[npm1], pathy[npm1];

		for (i=0; i<npm1; i++) {
			pathx[i] = (int)(node->path[i].x);
			pathy[i] = (int)(node->path[i].y);
		}
		
		drawpoly(fp, npm1, pathx, pathy, node->color, 1, node->color, node->dash_on, node->dash_off);
		
		}
	    break;
        case GFX_LINE: {
		int pathx[node->points], pathy[node->points];

		for (i=0; i < node->points; i++) {
			pathx[i] = (int)node->path[i].x;
			pathy[i] = (int)node->path[i].y;
		}

		for (i = 0; i < node->points; i++) {
			switch (node->path[i].code) {
			case ART_MOVETO_OPEN: /* fall-through */
			case ART_MOVETO:
				break;
			case ART_LINETO:
				if (i > 0) {
					drawline(fp,
			        		 pathx[i-1], pathy[i-1], pathx[i], pathy[i],
			        		 node->color, node->dash_on, node->dash_off);
				}
				break;
			case ART_CURVETO:
				fprintf(stderr, "cannot handle CURVETO"); /* unsupported */
				break;
			case ART_END:
				break;
			}
		}
	    }
	    break;
        case GFX_TEXT: {
		int x = (int)node->x, y = (int)node->y;
		drawtext(fp, node->text, x, y, node->color, node->angle, node->halign, node->valign);
	    }
	    break;
        }
        
        node = node->next;
    }
    finishDocument(fp);  
    return 0;    
}

#endif /* ENABLE_SVG_TINY */
