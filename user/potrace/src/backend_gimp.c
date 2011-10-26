/* Copyright (C) 2001-2007 Peter Selinger.
   This file is part of Potrace. It is free software and it is covered
   by the GNU General Public License. See the file COPYING for details. */

/* $Id: backend_gimp.c 147 2007-04-09 00:44:09Z selinger $ */

/* The gimppath backend of Potrace. Can be imported by Gimp with the
   "Import Path" feature (Layers -> Layers, Channels & Paths -> Paths
   -> Right-click -> Import Path) */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>

#include "main.h"
#include "backend_gimp.h"
#include "potracelib.h"
#include "lists.h"
#include "auxiliary.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

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

  q.x = (long)(floor(p.x*info.unit+.5));
  q.y = (long)(floor(p.y*info.unit+.5));
  return q;
}

static void gimppath_point(FILE *fout, int typ, dpoint_t p, trans_t t) {
  point_t q;

  q = unit(trans(p, t));

  fprintf(fout, "TYPE: %d X: %ld Y: %ld\n", typ, q.x, q.y);
}

/* ---------------------------------------------------------------------- */
/* functions for converting a path to a gimppath */

/* do one path. First should be 1 on the very first path, else 0. */
static int gimppath_path(FILE *fout, potrace_curve_t *curve, int first, trans_t t) {
  int i;
  dpoint_t *c, *c1;
  int m = curve->n;

  first = first ? 1 : 3;

  for (i=0; i<m; i++) {
    c = curve->c[i];
    c1 = curve->c[mod(i-1,m)];
    switch (curve->tag[i]) {
    case POTRACE_CORNER:
      gimppath_point(fout, first, c1[2], t);
      gimppath_point(fout, 2, c1[2], t);
      gimppath_point(fout, 2, c[1], t);
      gimppath_point(fout, 1, c[1], t);
      gimppath_point(fout, 2, c[1], t);
      gimppath_point(fout, 2, c[2], t);
      break;
    case POTRACE_CURVETO:
      gimppath_point(fout, first, c1[2], t);
      gimppath_point(fout, 2, c[0], t);
      gimppath_point(fout, 2, c[1], t);
      break;
    }
    first = 1;
  }
  return 0;
}

/* calculate number of Gimp control points in this path */
static int npoints(potrace_curve_t *curve) {
  int i;
  int n=0;
  int m = curve->n;

  for (i=0; i<m; i++) {
    switch (curve->tag[i]) {
    case POTRACE_CORNER:
      n += 6;
      break;
    case POTRACE_CURVETO:
      n += 3;
      break;
    }
  }
  return n;
}

/* ---------------------------------------------------------------------- */
/* Backend. */

/* public interface for GIMPPATH */
int page_gimp(FILE *fout, potrace_path_t *plist, imginfo_t *imginfo) {
  potrace_path_t *p;
  int first = 1;
  int n;
  trans_t t;
  double si, co;

  /* determine number of points */
  n = 0;
  list_forall (p, plist) {
    n += npoints(&p->curve);
  }  

  si = sin(info.angle/180*M_PI);
  co = cos(info.angle/180*M_PI);

  t.ox = max(0, si*imginfo->pixheight) + max(0, -co*imginfo->pixwidth);
  t.oy = max(0, co*imginfo->pixheight) + max(0, si*imginfo->pixwidth);
  t.dxx = co;
  t.dxy = -si;
  t.dyx = -si;
  t.dyy = -co;

  /* header */
  fprintf(fout, "Name: Potrace Imported Path\n");
  fprintf(fout, "#POINTS: %d\n", n);
  fprintf(fout, "CLOSED: 1\n");
  fprintf(fout, "DRAW: 0\n");
  fprintf(fout, "STATE: 4\n");

  /* write paths */
  list_forall (p, plist) {
    gimppath_path(fout, &p->curve, first, t);
    first = 0;
  }
  fflush(fout);

  return 0;
}

