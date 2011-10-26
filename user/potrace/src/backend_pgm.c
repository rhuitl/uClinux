/* Copyright (C) 2001-2007 Peter Selinger.
   This file is part of Potrace. It is free software and it is covered
   by the GNU General Public License. See the file COPYING for details. */

/* $Id: backend_pgm.c 147 2007-04-09 00:44:09Z selinger $ */

/* The PGM backend of Potrace. Here we custom-render a set of Bezier
   curves and output the result as a greymap. This is merely a
   convenience, as the same could be achieved by piping the EPS output
   through ghostscript. */

#include <math.h>

#include "backend_pgm.h"
#include "potracelib.h"
#include "lists.h"
#include "greymap.h"
#include "render.h"
#include "main.h"
#include "auxiliary.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

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

static void pgm_path(potrace_curve_t *curve, trans_t t, render_t *rm) {
  dpoint_t *c, c1[3];
  int i;
  int m = curve->n;
  
  c = curve->c[m-1];
  c1[2] = trans(c[2], t);
  render_moveto(rm, c1[2].x, c1[2].y);
  
  for (i=0; i<m; i++) {
    c = curve->c[i];
    switch (curve->tag[i]) {
    case POTRACE_CORNER:
      c1[1] = trans(c[1], t);
      c1[2] = trans(c[2], t);
      render_lineto(rm, c1[1].x, c1[1].y);
      render_lineto(rm, c1[2].x, c1[2].y);
      break;
    case POTRACE_CURVETO:
      c1[0] = trans(c[0], t);
      c1[1] = trans(c[1], t);
      c1[2] = trans(c[2], t);
      render_curveto(rm, c1[0].x, c1[0].y, c1[1].x, c1[1].y, c1[2].x, c1[2].y);
      break;
    }
  }
}

int page_pgm(FILE *fout, potrace_path_t *plist, imginfo_t *imginfo) {
  potrace_path_t *p;
  greymap_t *gm;
  render_t *rm;
  int w = (int)ceil(imginfo->trans.bb[0]+imginfo->lmar+imginfo->rmar);
  int h = (int)ceil(imginfo->trans.bb[1]+imginfo->tmar+imginfo->bmar);
  double xs, ys;  /* scaling factors */
  double si, co;
  trans_t t;
  int mode;
  char *comment = "created by "POTRACE" "VERSION", written by Peter Selinger 2001-2007";

  si = sin(info.angle/180*M_PI);
  co = cos(info.angle/180*M_PI);

  t.ox = imginfo->trans.orig[0]+imginfo->lmar;
  t.oy = imginfo->trans.orig[1]+imginfo->bmar;

  xs = imginfo->width / imginfo->pixwidth;
  ys = imginfo->height / imginfo->pixheight;

  t.dxx = co * xs;
  t.dxy = si * xs;
  t.dyx = -si * ys;
  t.dyy = co * ys;

  gm = gm_new(w, h);
  if (!gm) {
    return 1;
  }
  rm = render_new(gm);
  if (!rm) {
    return 1;
  }

  gm_clear(gm, 255); /* white */

  list_forall(p, plist) {
    pgm_path(&p->curve, t, rm);
  }

  render_close(rm);

  /* if negative orientation, make sure to invert effect of rendering */
  mode = xs * ys < 0 ? GM_MODE_NEGATIVE : GM_MODE_POSITIVE;

  gm_writepgm(fout, rm->gm, comment, 1, mode, info.gamma);

  render_free(rm);
  gm_free(gm);

  return 0;
}

