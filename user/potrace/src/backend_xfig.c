/* Copyright (C) 2001-2007 Peter Selinger.
   This file is part of Potrace. It is free software and it is covered
   by the GNU General Public License. See the file COPYING for details. */

/* $Id: backend_xfig.c 147 2007-04-09 00:44:09Z selinger $ */

/* The xfig backend of Potrace. */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>

#include "main.h"
#include "backend_xfig.h"
#include "potracelib.h"
#include "lists.h"
#include "auxiliary.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

struct pageformat_s {
  char *name;
  int w, h;
};
typedef struct pageformat_s pageformat_t;

/* page formats known by xfig, and their dimensions in postscript points */
static pageformat_t pageformat[] = {
  { "A9",        105,  149 },
  { "A8",        149,  211 },
  { "A7",        211,  298 },
  { "A6",        298,  421 },
  { "A5",        421,  595 },
  { "A4",        595,  842 },
  { "A3",        842, 1191 },
  { "A2",       1191, 1685 },
  { "A1",       1685, 2383 },
  { "A0",       2383, 3370 },

  { "B10",        91,  129 },
  { "B9",        129,  182 },
  { "B8",        182,  258 },
  { "B7",        258,  365 },
  { "B6",        365,  516 },
  { "B5",        516,  730 },
  { "B4",        730, 1032 },
  { "B3",       1032, 1460 },
  { "B2",       1460, 2064 },
  { "B1",       2064, 2920 },
  { "B0",       2920, 4127 },

  { "Letter",    612,  792 },
  { "Legal",     612, 1008 },
  { "Tabloid",   792, 1224 },
  { "A",         612,  792 },
  { "B",         792, 1224 },
  { "C",        1224, 1584 },
  { "D",        1584, 2448 },
  { "E",        2448, 3168 },

  { NULL, 0, 0 },
};

/* ---------------------------------------------------------------------- */
/* path-drawing auxiliary functions */

/* structure to hold an affine coordinate transformation */
struct trans_s {
  double ox, oy;             /* origin */
  double dxx, dxy, dyx, dyy; /* transformation matrix */
};
typedef struct trans_s trans_t;

static inline dpoint_t trans(dpoint_t p, trans_t t) {
  dpoint_t res;

  res.x = t.ox + p.x * t.dxx + p.y * t.dyx;
  res.y = t.oy + p.x * t.dxy + p.y * t.dyy;
  return res;
}

/* coordinate quantization */
static inline point_t unit(dpoint_t p) {
  point_t q;

  q.x = (long)(floor(p.x+.5));
  q.y = (long)(floor(p.y+.5));
  return q;
}

static void xfig_point(FILE *fout, dpoint_t p, trans_t t) {
  point_t q;

  q = unit(trans(p, t));

  fprintf(fout, "%ld %ld\n", q.x, q.y);
}

/* ---------------------------------------------------------------------- */
/* functions for converting a path to a xfig */

/* calculate number of xfig control points in this path */
static int npoints(potrace_curve_t *curve, int m) {
  int i;
  int n=0;

  for (i=0; i<m; i++) {
    switch (curve->tag[i]) {
    case POTRACE_CORNER:
      n += 1;
      break;
    case POTRACE_CURVETO:
      n += 2;
      break;
    }
  }
  return n;
}

/* do one path. First should be 1 on the very first path, else 0. */
static int xfig_path(FILE *fout, potrace_curve_t *curve, trans_t t, int sign) {
  int i;
  dpoint_t *c;
  int m = curve->n;

  fprintf(fout, "3 1 0 0 0 %d 50 0 20 0.000 0 0 0 %d\n", sign=='+' ? 32 : 33, npoints(curve, m));

  for (i=0; i<m; i++) {
    c = curve->c[i];
    switch (curve->tag[i]) {
    case POTRACE_CORNER:
      xfig_point(fout, c[1], t);
      break;
    case POTRACE_CURVETO:
      xfig_point(fout, c[0], t);
      xfig_point(fout, c[1], t);
      break;
    }
  }
  for (i=0; i<m; i++) {
    switch (curve->tag[i]) {
    case POTRACE_CORNER:
      fprintf(fout, "0\n");
      break;
    case POTRACE_CURVETO:
      fprintf(fout, "1 1\n");
      break;
    }
  }
  return 0;
}

/* ---------------------------------------------------------------------- */
/* Backend. */

/* public interface for XFIG */
int page_xfig(FILE *fout, potrace_path_t *plist, imginfo_t *imginfo) {
  potrace_path_t *p;
  trans_t t;
  double si, co;
  double origx = imginfo->trans.orig[0] + imginfo->lmar;
  double origy = - imginfo->trans.orig[1] - imginfo->bmar + info.paperheight;
  double scalex = imginfo->width / imginfo->pixwidth;
  double scaley = imginfo->height / imginfo->pixheight;
  char *formatname;
  int best, penalty;
  pageformat_t *f;
  int i;
  int x0, y0, x1, y1;  /* in xfig's coordinates */
  
  si = sin(info.angle/180*M_PI);
  co = cos(info.angle/180*M_PI);
  
  t.ox = 1200/72.0 * origx;
  t.oy = 1200/72.0 * origy;
  t.dxx = 1200/72.0 * scalex * co;
  t.dxy = 1200/72.0 * scalex * -si;
  t.dyx = 1200/72.0 * scaley * -si;
  t.dyy = 1200/72.0 * scaley * -co;

  x0 = (int)(1200/72.0 * (origx - imginfo->trans.orig[0]));
  y0 = (int)(1200/72.0 * (origy + imginfo->trans.orig[1]));
  x1 = x0 + (int)(1200/72.0 * imginfo->trans.bb[0]);
  y1 = y0 - (int)(1200/72.0 * imginfo->trans.bb[1]);

  best = -1;
  formatname = "Letter";

  /* find closest page format */
  for (i=0; pageformat[i].name; i++) {
    f = &pageformat[i];
    if (f->w >= info.paperwidth-1 && f->h >= info.paperheight-1) {
      penalty = f->w + f->h;
      if (best == -1 || penalty < best) {
	best = penalty;
	formatname = f->name;
      }
    }
  }

  /* header */
  fprintf(fout, "#FIG 3.2\n");
  fprintf(fout, "#created by "POTRACE" "VERSION", written by Peter Selinger 2001-2007\n");
  fprintf(fout, "Portrait\n");
  fprintf(fout, "Center\n");
  fprintf(fout, "Inches\n");
  fprintf(fout, "%s\n", formatname);
  fprintf(fout, "100.0\n");
  fprintf(fout, "Single\n");
  fprintf(fout, "-2\n");
  fprintf(fout, "1200 2\n");  /* 1200 pixels per inch */
  fprintf(fout, "0 32 #%06x\n", info.color);
  fprintf(fout, "0 33 #%06x\n", info.fillcolor);
  fprintf(fout, "6 %d %d %d %d\n", x0-75, y1-35, x1+75, y0+35); /* bounding box */

  /* write paths. Note: can never use "opticurve" with this backend -
     it just does not approximate Bezier curves closely enough.  */
  list_forall (p, plist) {
    xfig_path(fout, &p->curve, t, p->sign);
  }

  fprintf(fout, "-6\n"); /* end bounding box */

  fflush(fout);

  return 0;
}
