/* Copyright (C) 2001-2007 Peter Selinger.
   This file is part of Potrace. It is free software and it is covered
   by the GNU General Public License. See the file COPYING for details. */

/* $Id: main.c 147 2007-04-09 00:44:09Z selinger $ */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <math.h>

#include "main.h"
#include "potracelib.h"
#include "backend_pdf.h"
#include "backend_eps.h"
#include "backend_pgm.h"
#include "backend_svg.h"
#include "backend_gimp.h"
#include "backend_xfig.h"
#include "potracelib.h"
#include "bitmap_io.h"
#include "bitmap.h"
#include "platform.h"
#include "auxiliary.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define UNDEF ((double)(1e30))   /* a value to represent "undefined" */
#define INFTY ((double)(1e30))   /* a value to represent +infinity */

struct info_s info;

#define COL0 "\033[G"  /* reset cursor to column 0 */

/* ---------------------------------------------------------------------- */
/* callback function for progress bar */

struct simple_progress_s {
  char name[22];          /* filename for status bar */
  double dnext;           /* threshold value for next tick */
};
typedef struct simple_progress_s simple_progress_t;

/* print a simple progress bar. This is a callback function that is
   potentially called often; thus, it has been optimized for the
   typical case, which is when the progress bar does not need updating. */
static void simple_progress(double d, void *data) {
  simple_progress_t *p = (simple_progress_t *)data;
  static char b[] = "========================================";
  int tick;    /* number of visible tickmarks, 0..40 */
  int perc;    /* visible percentage, 0..100 */

  /* note: the 0.01 and 0.025 ensure that we always end on 40
     tickmarks and 100%, despite any rounding errors. The 0.995
     ensures that tick always increases when d >= p->dnext. */
  if (d >= p->dnext) {
    tick = (int) floor(d*40+0.01);
    perc = (int) floor(d*100+0.025);
    fprintf(stderr, "%-21s |%-40s| %d%% "COL0"", p->name, b+40-tick, perc);
    p->dnext = (tick+0.995) / 40.0;
  }
}

/* Initialize parameters for simple progress bar. The caller passes an
   allocated simple_progress_t structure to avoid having to malloc it
   here and free it later. */
static inline void init_progress(potrace_progress_t *prog, simple_progress_t *p, const char *filename, int count) {
  const char *q, *s;
  int len;

  /* initialize callback function's data */
  p->dnext = 0;

  if (count != 0) {
    sprintf(p->name, " (p.%d):", count+1);
  } else {
    s = filename;
    if ((q = strrchr(s, '/')) != NULL) {
      s = q+1;
    }
    len = strlen(s);
    strncpy(p->name, s, 21);
    p->name[20] = 0;
    if (len > 20) {
      p->name[17] = '.';
      p->name[18] = '.';
      p->name[19] = '.';
    }
    strcat(p->name, ":");
  }

  /* initialize progress parameters */
  prog->callback = &simple_progress;
  prog->data = (void *)p;
  prog->min = 0.0;
  prog->max = 1.0;
  prog->epsilon = 0.0;
  
  /* draw first progress bar */
  simple_progress(0.0, prog->data);
  return;
}

/* ---------------------------------------------------------------------- */
/* some data structures for option processing */

struct pageformat_s {
  char *name;
  int w, h;
};
typedef struct pageformat_s pageformat_t;

/* dimensions of the various page formats, in postscript points */
static pageformat_t pageformat[] = {
  { "a4",        595,  842 },
  { "a3",        842, 1191 },
  { "a5",        421,  595 },
  { "b5",        516,  729 },
  { "letter",    612,  792 },
  { "legal",     612, 1008 },
  { "tabloid",   792, 1224 },
  { "statement", 396,  612 },
  { "executive", 540,  720 },
  { "folio",     612,  936 },
  { "quarto",    610,  780 },
  { "10x14",     720, 1008 },
  { NULL, 0, 0 },
};

struct turnpolicy_s {
  char *name;
  int n;
};
typedef struct turnpolicy_s turnpolicy_t;

/* names of turn policies */
static turnpolicy_t turnpolicy[] = {
  {"black",    POTRACE_TURNPOLICY_BLACK},
  {"white",    POTRACE_TURNPOLICY_WHITE},
  {"left",     POTRACE_TURNPOLICY_LEFT},
  {"right",    POTRACE_TURNPOLICY_RIGHT},
  {"minority", POTRACE_TURNPOLICY_MINORITY},
  {"majority", POTRACE_TURNPOLICY_MAJORITY},
  {"random",   POTRACE_TURNPOLICY_RANDOM},
  {NULL, 0},
};

/* backends and their characteristics */
struct backend_s {
  char *name;       /* name of this backend */
  char *ext;        /* file extension */
  int fixed;        /* fixed page size backend? */
  int pixel;        /* pixel-based backend? */
  int multi;        /* multi-page backend? */
  int (*init_f)(FILE *fout);                 /* initialization function */
  int (*page_f)(FILE *fout, potrace_path_t *plist, imginfo_t *imginfo);
                                             /* per-bitmap function */
  int (*term_f)(FILE *fout);                 /* finalization function */
  int opticurve;    /* opticurve capable (true Bezier curves?) */
};
typedef struct backend_s backend_t;  

static backend_t backend[] = {
  {"eps",        ".eps",      0, 0, 0, NULL,    page_eps,   NULL,     1},
  {"postscript", ".ps",       1, 0, 1, init_ps, page_ps,    term_ps,  1},
  {"ps",         ".ps",       1, 0, 1, init_ps, page_ps,    term_ps,  1},
  {"pdf",        ".pdf",      0, 0, 1, init_pdf,page_pdf,   term_pdf, 1},
  {"svg",        ".svg",      0, 0, 0, NULL,    page_svg,   NULL,     1},
  {"pgm",        ".pgm",      0, 1, 1, NULL,    page_pgm,   NULL,     1},
  {"gimppath",   ".gimppath", 0, 1, 0, NULL,    page_gimp,  NULL,     1},
  {"xfig",       ".fig",      1, 0, 0, NULL,    page_xfig,  NULL,     0},
  {NULL, NULL, 0, 0, 0, NULL, NULL, NULL},
};

/* look up a backend by name. If found, return 0 and set *bp. If not
   found leave *bp unchanged and return 1, or 2 on ambiguous
   prefix. */
static int backend_lookup(char *name, backend_t **bp) {
  int i;
  int m=0;  /* prefix matches */
  backend_t *b = NULL;

  for (i=0; backend[i].name; i++) {
    if (strcasecmp(backend[i].name, name)==0) {
      *bp = &backend[i];
      return 0;
    } else if (strncasecmp(backend[i].name, name, strlen(name))==0) {
      m++;
      b = &backend[i];
    }      
  }
  /* if there was no exact match, and exactly one prefix match, use that */
  if (m==1) {  
    *bp = b;
    return 0;
  } else if (m) {
    return 2;
  } else {
    return 1;
  }
}

/* list all available backends by name, in a comma separated list.
   Assume the cursor starts in column j, and break lines at length
   linelen. Do not output any trailing punctuation. Return the column
   the cursor is in. */
static int backend_list(FILE *fout, int j, int linelen) {
  int i;

  for (i=0; backend[i].name; i++) {
    if (j + (int)strlen(backend[i].name) > linelen) {
      fprintf(fout, "\n");
      j = 0;
    }
    j += fprintf(fout, "%s", backend[i].name);
    if (backend[i+1].name) {
      j += fprintf(fout, ", ");
    }
  }
  return j;
}

/* ---------------------------------------------------------------------- */
/* some info functions */

static void license(FILE *f) {
  fprintf(f, 
  "This program is free software; you can redistribute it and/or modify\n"
  "it under the terms of the GNU General Public License as published by\n"
  "the Free Software Foundation; either version 2 of the License, or\n"
  "(at your option) any later version.\n"
  "\n"
  "This program is distributed in the hope that it will be useful,\n"
  "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
  "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
  "GNU General Public License for more details.\n"
  "\n"
  "You should have received a copy of the GNU General Public License\n"
  "along with this program; if not, write to the Free Software\n"
  "Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.\n"
	  );
}

static void show_defaults(FILE *f) {
  fprintf(f, "This version of Potrace was compiled with the following defaults:\n");
  fprintf(f, "Default unit: "DEFAULT_DIM_NAME"\n");
  fprintf(f, "Default page size: "DEFAULT_PAPERFORMAT"\n");
}

static void usage(FILE *f) {
  int j;

  fprintf(f, "Usage: "POTRACE" [options] [file...]\n");
  fprintf(f, "General options:\n");
  fprintf(f, " -h, --help                 - print this help message and exit\n");
  fprintf(f, " -v, --version              - print version info and exit\n");
  fprintf(f, " -l, --license              - print license info and exit\n");
  fprintf(f, " -V, --show-defaults        - print compiled-in defaults and exit\n");
  fprintf(f, " --progress                 - show progress bar\n");
  fprintf(f, "Input/output options:\n");
  fprintf(f, " -o, --output <file>        - output to file\n");
  fprintf(f, "Backend selection:\n");
  fprintf(f, " -e, --eps                  - EPS backend (encapsulated postscript) (default)\n");
  fprintf(f, " -p, --postscript           - Postscript backend\n");
  fprintf(f, " -s, --svg                  - SVG backend (scalable vector graphics)\n");
  fprintf(f, " -g, --pgm                  - PGM backend (portable greymap)\n");
  fprintf(f, " -b, --backend <name>       - select backend by name\n");
  fprintf(f, "Algorithm options:\n");
  fprintf(f, " -z, --turnpolicy <policy>  - how to resolve ambiguities in path decomposition\n");
  fprintf(f, " -t, --turdsize <n>         - suppress speckles of up to this size (default 2)\n");
  fprintf(f, " -a, --alphamax <n>         - corner threshold parameter (default 1)\n");
  fprintf(f, " -n, --longcurve            - turn off curve optimization\n");
  fprintf(f, " -O, --opttolerance <n>     - curve optimization tolerance (default 0.2)\n");
  fprintf(f, " -u, --unit <n>             - quantize output to 1/unit pixels (default 10)\n");
  fprintf(f, " -d, --debug <n>            - produce debugging output of type n (n=1,2,3)\n");
  fprintf(f, "Scaling and placement options:\n");
  fprintf(f, " -W, --width <dim>          - width of output image\n");
  fprintf(f, " -H, --height <dim>         - height of output image\n");
  fprintf(f, " -r, --resolution <n>[x<n>] - resolution (in dpi)\n");
  fprintf(f, " -x, --scale <n>[x<n>]      - scaling factor (pgm backend)\n");
  fprintf(f, " -S, --stretch <n>          - yresolution/xresolution\n");
  fprintf(f, " -A, --rotate <angle>       - rotate counterclockwise by angle\n");
  fprintf(f, " -M, --margin <dim>         - margin\n");
  fprintf(f, " -L, --leftmargin <dim>     - left margin\n");
  fprintf(f, " -R, --rightmargin <dim>    - right margin\n");
  fprintf(f, " -T, --topmargin <dim>      - top margin\n");
  fprintf(f, " -B, --bottommargin <dim>   - bottom margin\n");
  fprintf(f, "Output options, supported by some backends:\n");
  fprintf(f, " -C, --color #rrggbb        - set line color (default black)\n");
  fprintf(f, " --fillcolor #rrggbb        - set fill color (default transparent)\n");
  fprintf(f, " --opaque                   - make white shapes opaque\n");
  fprintf(f, " --group                    - group related paths together\n");
  fprintf(f, "Postscript/EPS options:\n");
  fprintf(f, " -P, --pagesize <format>    - page size (default is "DEFAULT_PAPERFORMAT")\n");
  fprintf(f, " -c, --cleartext            - do not compress the output\n");
  fprintf(f, " -2, --level2               - use postscript level 2 compression (default)\n");
#ifdef HAVE_ZLIB
  fprintf(f, " -3, --level3               - use postscript level 3 compression\n");
#endif
  fprintf(f, " -q, --longcoding           - do not optimize for file size\n");
  fprintf(f, "PGM options:\n");
  fprintf(f, " -G, --gamma <n>            - gamma value for anti-aliasing (default 2.2)\n");
  fprintf(f, "Frontend options:\n");
  fprintf(f, " -k, --blacklevel <n>       - black/white cutoff in input file (default 0.5)\n");
  fprintf(f, " -i, --invert               - invert bitmap\n");
  fprintf(f, "\n");
  fprintf(f, "Dimensions can have optional units, e.g. 6.5in, 15cm, 100pt.\n");
  fprintf(f, "Default is "DEFAULT_DIM_NAME" (or pixels for pgm and gimppath backends).\n");
  fprintf(f, "Possible input file formats are: pnm (pbm, pgm, ppm), bmp.\n");
  j = fprintf(f, "Backends are: ");
  backend_list(f, j, 70);
  fprintf(f, ".\n");
}

/* ---------------------------------------------------------------------- */
/* auxiliary functions for parameter parsing */

/* parse a dimension of the kind "1.5in", "7cm", etc. Return result in
   postscript points (=1/72 in). If endptr!=NULL, store pointer to
   next character in *endptr in the manner of strtod(3). */
static dim_t parse_dimension(char *s, char **endptr) {
  char *p;
  dim_t res;

  res.x = strtod(s, &p);
  res.d = 0;
  if (p!=s) {
    if (!strncasecmp(p, "in", 2)) {
      res.d = DIM_IN;
      p += 2;
    } else if (!strncasecmp(p, "cm", 2)) {
      res.d = DIM_CM;
      p += 2;
    } else if (!strncasecmp(p, "mm", 2)) {
      res.d = DIM_MM;
      p += 2;
    } else if (!strncasecmp(p, "pt", 2)) {
      res.d = DIM_PT;
      p += 2;
    }
  }
  if (endptr!=NULL) {
    *endptr = p;
  }
  return res;
}

/* parse a pair of dimensions, such as "8.5x11in", "30mmx4cm" */
static void parse_dimensions(char *s, char **endptr, dim_t *dxp, dim_t *dyp) {
  char *p, *q;
  dim_t dx, dy;

  dx = parse_dimension(s, &p);
  if (p==s) {
    goto fail;
  }
  if (*p != 'x') {
    goto fail;
  }
  p++;
  dy = parse_dimension(p, &q);
  if (q==p) {
    goto fail;
  }
  if (dx.d && !dy.d) {
    dy.d = dx.d;
  } else if (!dx.d && dy.d) {
    dx.d = dy.d;
  }
  *dxp = dx;
  *dyp = dy;
  if (endptr != NULL) {
    *endptr = q;
  }
  return;

 fail:
  dx.x = dx.d = dy.x = dy.d = 0;
  *dxp = dx;
  *dyp = dy;
  if (endptr != NULL) {
    *endptr = s;
  }
  return;
}

static inline double double_of_dim(dim_t d, double def) {
  if (d.d) {
    return d.x * d.d;
  } else {
    return d.x * def;
  }
}

static int parse_color(char *s) {
  int i, d;
  int col = 0;

  if (s[0] != '#' || strlen(s) != 7) {
    return -1;
  }
  for (i=0; i<6; i++) {
    d = s[6-i];
    if (d >= '0' && d <= '9') {
      col |= (d-'0') << (4*i);
    } else if (d >= 'a' && d <= 'f') {
      col |= (d-'a'+10) << (4*i);
    } else if (d >= 'A' && d <= 'F') {
      col |= (d-'A'+10) << (4*i);
    } else {
      return -1;
    }
  }
  return col;
}  

/* ---------------------------------------------------------------------- */
/* option processing */

/* codes for options that don't have short form */
#define OPT_GROUP     300
#define OPT_OPAQUE    301
#define OPT_FILLCOLOR 302
#define OPT_PROGRESS  303

static struct option longopts[] = {
  {"help",          0, 0, 'h'},
  {"version",       0, 0, 'v'},
  {"license",       0, 0, 'l'},
  {"show-defaults", 0, 0, 'V'},
  {"progress",      0, 0, OPT_PROGRESS},
  {"width",         1, 0, 'W'},
  {"height",        1, 0, 'H'},
  {"resolution",    1, 0, 'r'},
  {"scale",         1, 0, 'x'},
  {"stretch",       1, 0, 'S'},
  {"margin",        1, 0, 'M'},
  {"leftmargin",    1, 0, 'L'},
  {"rightmargin",   1, 0, 'R'},
  {"topmargin",     1, 0, 'T'},
  {"bottommargin",  1, 0, 'B'},
  {"rotate",        1, 0, 'A'},
  {"pagesize",      1, 0, 'P'},
  {"turdsize",      1, 0, 't'},
  {"unit",          1, 0, 'u'},
  {"cleartext",     0, 0, 'c'},
  {"level2",        0, 0, '2'},
  {"level3",        0, 0, '3'},
  {"eps",           0, 0, 'e'},
  {"postscript",    0, 0, 'p'},
  {"svg",           0, 0, 's'},
  {"pgm",           0, 0, 'g'},
  {"backend",       1, 0, 'b'},
  {"debug",         1, 0, 'd'},
  {"color",         1, 0, 'C'},
  {"fillcolor",     1, 0, OPT_FILLCOLOR},
  {"turnpolicy",    1, 0, 'z'},
  {"gamma",         1, 0, 'G'},
  {"longcurve",     0, 0, 'n'},
  {"longcoding",    0, 0, 'q'},
  {"alphamax",      1, 0, 'a'},
  {"opttolerance",  1, 0, 'O'},
  {"output",        1, 0, 'o'},
  {"blacklevel",    1, 0, 'k'},
  {"invert",        0, 0, 'i'},
  {"opaque",        0, 0, OPT_OPAQUE},
  {"group",         0, 0, OPT_GROUP},

  {0, 0, 0, 0}
};

static char *shortopts = "hvlVW:H:r:x:S:M:L:R:T:B:A:P:t:u:c23epsgb:d:C:z:G:nqa:O:o:k:i";

static void dopts(int ac, char *av[]) {
  int c;
  char *p;
  int i, j, r;
  dim_t dim, dimx, dimy;
  int matches, bestmatch;

  /* defaults */
  backend_lookup("eps", &info.backend);
  info.debug = 0;
  info.width_d.x = UNDEF;
  info.height_d.x = UNDEF;
  info.rx = UNDEF;
  info.ry = UNDEF;
  info.sx = UNDEF;
  info.sy = UNDEF;
  info.stretch = 1;
  info.lmar_d.x = UNDEF;
  info.rmar_d.x = UNDEF;
  info.tmar_d.x = UNDEF;
  info.bmar_d.x = UNDEF;
  info.angle = 0;
  info.paperwidth = DEFAULT_PAPERWIDTH;
  info.paperheight = DEFAULT_PAPERHEIGHT;
  info.unit = 10;
  info.compress = 1;
  info.pslevel = 2;
  info.color = 0x000000;
  info.gamma = 2.2;
  info.param = potrace_param_default();
  if (!info.param) {
    fprintf(stderr, ""POTRACE": %s\n", strerror(errno));
    exit(1);
  }
  info.longcoding = 0;
  info.outfile = NULL;
  info.blacklevel = 0.5;
  info.invert = 0;
  info.opaque = 0;
  info.group = 0;
  info.fillcolor = 0xffffff;
  info.progress = 0;

  while ((c = getopt_long(ac, av, shortopts, longopts, NULL)) != -1) {
    switch (c) {
    case 'h':
      fprintf(stdout, ""POTRACE" "VERSION". Transforms bitmaps into vector graphics.\n\n");
      usage(stdout);
      exit(0);
      break;
    case 'v':
      fprintf(stdout, ""POTRACE" "VERSION". Copyright (C) 2001-2007 Peter Selinger.\n");
      fprintf(stdout, "Library version: %s\n", potrace_version());
      exit(0);
      break;
    case 'l':
      fprintf(stdout, ""POTRACE" "VERSION". Copyright (C) 2001-2007 Peter Selinger.\n\n");
      license(stdout);
      exit(0);
      break;
    case 'V':
      fprintf(stdout, ""POTRACE" "VERSION". Copyright (C) 2001-2007 Peter Selinger.\n");
      show_defaults(stdout);
      exit(0);
      break;
    case OPT_PROGRESS:
      info.progress = 1;
      break;
    case 'W':
      info.width_d = parse_dimension(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid dimension -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'H':
      info.height_d = parse_dimension(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid dimension -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'r':
      parse_dimensions(optarg, &p, &dimx, &dimy);
      if (*p == 0 && dimx.d == 0 && dimy.d == 0) {
	info.rx = dimx.x;
	info.ry = dimy.x;
	break;
      }
      dim = parse_dimension(optarg, &p);
      if (*p == 0 && dim.d == 0) {
	info.rx = info.ry = dim.x;
	break;
      }
      fprintf(stderr, ""POTRACE": invalid resolution -- %s\n", optarg);
      exit(1);
      break;
    case 'x':
      parse_dimensions(optarg, &p, &dimx, &dimy);
      if (*p == 0 && dimx.d == 0 && dimy.d == 0) {
	info.sx = dimx.x;
	info.sy = dimy.x;
	break;
      }
      dim = parse_dimension(optarg, &p);
      if (*p == 0 && dim.d == 0) {
	info.sx = info.sy = dim.x;
	break;
      }
      fprintf(stderr, ""POTRACE": invalid scaling factor -- %s\n", optarg);
      exit(1);
      break;
    case 'S':
      info.stretch = atof(optarg);
      break;
    case 'M':
      info.lmar_d = parse_dimension(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid dimension -- %s\n", optarg);
	exit(1);
      }
      info.rmar_d = info.tmar_d = info.bmar_d = info.lmar_d;
      break;
    case 'L':
      info.lmar_d = parse_dimension(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid dimension -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'R':
      info.rmar_d = parse_dimension(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid dimension -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'T':
      info.tmar_d = parse_dimension(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid dimension -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'B':
      info.bmar_d = parse_dimension(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid dimension -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'A':
      info.angle = strtod(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid angle -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'P':
      matches = 0;
      bestmatch = 0;
      for (i=0; pageformat[i].name!=NULL; i++) {
        if (strcasecmp(pageformat[i].name, optarg)==0) {
          matches = 1;
          bestmatch = i;
          break;
	} else if (strncasecmp(pageformat[i].name, optarg, strlen(optarg))==0) {
	  /* don't allow partial match on "10x14" */
	  if (optarg[0] != '1') {
	    matches++;
	    bestmatch = i;
	  }
	}
      }
      if (matches == 1) {
	info.paperwidth = pageformat[bestmatch].w;
	info.paperheight = pageformat[bestmatch].h;
	break;
      }
      parse_dimensions(optarg, &p, &dimx, &dimy);
      if (*p == 0) {
	info.paperwidth = (int)rint(double_of_dim(dimx, DEFAULT_DIM));
	info.paperheight = (int)rint(double_of_dim(dimy, DEFAULT_DIM));
	break;
      }
      if (matches == 0) {
	fprintf(stderr, ""POTRACE": unrecognized page format -- %s\n", optarg);
      } else {
	fprintf(stderr, ""POTRACE": ambiguous page format -- %s\n", optarg);
      }
      j = fprintf(stderr, "Use one of: ");
      for (i=0; pageformat[i].name!=NULL; i++) {
	if (j + strlen(pageformat[i].name) > 75) {
	  fprintf(stderr, "\n");
	  j = 0;
	}
	j += fprintf(stderr, "%s, ", pageformat[i].name);
      }
      fprintf(stderr, "or specify <dim>x<dim>.\n");
      exit(1);
      break;
    case 't':
      info.param->turdsize = atoi(optarg);
      break;
    case 'u':
      info.unit = strtod(optarg, &p);
      if (*p) {
        fprintf(stderr, ""POTRACE": invalid unit -- %s\n", optarg);
        exit(1);
      }
      break;
    case 'c':
      info.pslevel = 2;
      info.compress = 0;
      break;
    case '2':
      info.pslevel = 2;
      info.compress = 1;
      break;
    case '3':
#ifdef HAVE_ZLIB
      info.pslevel = 3;
      info.compress = 1;
#else
      fprintf(stderr, ""POTRACE": option -3 not supported, using -2 instead.\n");
      info.pslevel = 2;
      info.compress = 1;
#endif
      break;
    case 'e':
      backend_lookup("eps", &info.backend);
      break;
    case 'p':
      backend_lookup("postscript", &info.backend);
      break;
    case 's':
      backend_lookup("svg", &info.backend);
      break;
    case 'g':
      backend_lookup("pgm", &info.backend);
      break;
    case 'b':
      r = backend_lookup(optarg, &info.backend);
      if (r==1 || r==2) {
	if (r==1) {
	  fprintf(stderr, ""POTRACE": unrecognized backend -- %s\n", optarg);
	} else {
	  fprintf(stderr, ""POTRACE": ambiguous backend -- %s\n", optarg);
	}
	j = fprintf(stderr, "Use one of: ");
	backend_list(stderr, j, 70);
	fprintf(stderr, ".\n");
	exit(1);
      }
      break;
    case 'd':
      info.debug = atoi(optarg);
      break;
    case 'C':
      info.color = parse_color(optarg);
      if (info.color == -1) {
	fprintf(stderr, ""POTRACE": invalid color -- %s\n", optarg);
	exit(1);
      }
      break;
    case OPT_FILLCOLOR:
      info.fillcolor = parse_color(optarg);
      if (info.fillcolor == -1) {
	fprintf(stderr, ""POTRACE": invalid color -- %s\n", optarg);
	exit(1);
      }
      info.opaque = 1;
      break;
    case 'z':
      matches = 0;
      bestmatch = 0;
      for (i=0; turnpolicy[i].name!=NULL; i++) {
        if (strcasecmp(turnpolicy[i].name, optarg)==0) {
	  matches = 1;
	  bestmatch = i;
          break;
	} else if (strncasecmp(turnpolicy[i].name, optarg, strlen(optarg))==0) {
	  matches++;
	  bestmatch = i;
	}
      }
      if (matches == 1) {
	info.param->turnpolicy = turnpolicy[bestmatch].n;
	break;
      }
      if (matches == 0) {
	fprintf(stderr, ""POTRACE": unrecognized turnpolicy -- %s\n", optarg);
      } else {
	fprintf(stderr, ""POTRACE": ambiguous turnpolicy -- %s\n", optarg);
      }
      j = fprintf(stderr, "Use one of: ");
      for (i=0; turnpolicy[i].name!=NULL; i++) {
	if (j + strlen(turnpolicy[i].name) > 75) {
	  fprintf(stderr, "\n");
	  j = 0;
	}
	j += fprintf(stderr, "%s%s", turnpolicy[i].name, turnpolicy[i+1].name ? ", " : "");
      }
      fprintf(stderr, ".\n");
      exit(1);
      break;
    case 'G':
      info.gamma = atof(optarg);
      break;
    case 'n':
      info.param->opticurve = 0;
      break;
    case 'q':
      info.longcoding = 1;
      break;
    case 'a':
      info.param->alphamax = strtod(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid alphamax -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'O':
      info.param->opttolerance = strtod(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid opttolerance -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'o':
      free(info.outfile);
      info.outfile = strdup(optarg);
      break;
    case 'k':
      info.blacklevel = strtod(optarg, &p);
      if (*p) {
	fprintf(stderr, ""POTRACE": invalid blacklevel -- %s\n", optarg);
	exit(1);
      }
      break;
    case 'i':
      info.invert = 1;
      break;
    case OPT_OPAQUE:
      info.opaque = 1;
      break;
    case OPT_GROUP:
      info.group = 1;
      break;
    case '?':
      fprintf(stderr, "Try --help for more info\n");
      exit(1);
      break;
    default:
      fprintf(stderr, ""POTRACE": Unimplemented option -- %c\n", c);
      exit(1);
    }
  }
  info.infiles = &av[optind];
  info.infilecount = ac-optind;
}

/* ---------------------------------------------------------------------- */
/* calculations with bitmap dimensions, positioning etc */

/* consider a rectangle spanned by the vectors (w,0) and (0,h). Rotate
   it counterclockwise by angle alpha. Then set the rect_t structure
   to the resulting rectangle, setting its bounding box, origin,
   x-basis and y-basis. */

static void rotate_dim(double alpha, double w, double h, rect_t *r) { 
  double s, c, x0, x1, y0, y1;

  s = sin(alpha/180*M_PI);
  c = cos(alpha/180*M_PI);

  /* apply the transformation matrix to the basis vectors */
  x0 = c*w;
  x1 = s*w;
  y0 = -s*h;
  y1 = c*h;

  /* determine bounding box and origin relative to bounding box */
  r->bb[0] = fabs(x0) + fabs(y0);
  r->bb[1] = fabs(x1) + fabs(y1);
  r->orig[0] = - min(x0,0) - min(y0,0);
  r->orig[1] = - min(x1,0) - min(y1,0);
}
  
/* determine the dimensions of the output based on command line and
   image dimensions */
static void calc_dimensions(imginfo_t *imginfo) {
  double dim_def;
  double maxwidth, maxheight, sc;
  rect_t r;

  /* we take care of a special case: if one of the image dimensions is
     0, we change it to 1. Such an image is empty anyway, so there
     will be 0 paths in it. Changing the dimensions avoids division by
     0 error in calculating scaling factors, bounding boxes and
     such. This doesn't quite do the right thing in all cases, but it
     is better than causing overflow errors or "nan" output in
     backends.  Human users don't tend to process images of size 0
     anyway; they might occur in some pipelines. */
  if (imginfo->pixwidth == 0) {
    imginfo->pixwidth = 1;
  }
  if (imginfo->pixheight == 0) {
    imginfo->pixheight = 1;
  }

  /* set the default dimension for width, height, margins */
  if (info.backend->pixel) {
    dim_def = DIM_PT;
  } else {
    dim_def = DEFAULT_DIM;
  }

  /* apply default dimension to width, height, margins */
  imginfo->width = info.width_d.x == UNDEF ? UNDEF : double_of_dim(info.width_d, dim_def);
  imginfo->height = info.height_d.x == UNDEF ? UNDEF : double_of_dim(info.height_d, dim_def);
  imginfo->lmar = info.lmar_d.x == UNDEF ? UNDEF : double_of_dim(info.lmar_d, dim_def);
  imginfo->rmar = info.rmar_d.x == UNDEF ? UNDEF : double_of_dim(info.rmar_d, dim_def);
  imginfo->tmar = info.tmar_d.x == UNDEF ? UNDEF : double_of_dim(info.tmar_d, dim_def);
  imginfo->bmar = info.bmar_d.x == UNDEF ? UNDEF : double_of_dim(info.bmar_d, dim_def);

  /* determine width and height from desired resolution / scaling
     factor, if given */
  if (info.backend->pixel) {
    if (imginfo->width == UNDEF && info.sx != UNDEF) {
      imginfo->width = imginfo->pixwidth * info.sx;
    }
    if (imginfo->height == UNDEF && info.sy != UNDEF) {
      imginfo->height = imginfo->pixheight * info.sy;
    }
  } else {
    if (imginfo->width == UNDEF && info.rx != UNDEF) {
      imginfo->width = imginfo->pixwidth / info.rx * 72;
    }
    if (imginfo->height == UNDEF && info.ry != UNDEF) {
      imginfo->height = imginfo->pixheight / info.ry * 72;
    }
  }

  /* if one of width/height is specified, determine the other */
  if (imginfo->width == UNDEF && imginfo->height != UNDEF) {
    imginfo->width = imginfo->height / imginfo->pixheight * imginfo->pixwidth / info.stretch;
  } else if (imginfo->width != UNDEF && imginfo->height == UNDEF) {
    imginfo->height = imginfo->width / imginfo->pixwidth * imginfo->pixheight * info.stretch;
  }

  /* if width and height are still variable, figure them out */
  if (imginfo->width == UNDEF && imginfo->height == UNDEF) {
   
    if (info.backend->fixed) {

      /* in fixed-size backends, try to squeeze it between margins */
      maxwidth = UNDEF;
      maxheight = UNDEF;
      
      if (imginfo->lmar != UNDEF && imginfo->rmar != UNDEF) {
	maxwidth = info.paperwidth - imginfo->lmar - imginfo->rmar;
      } 
      if (imginfo->bmar != UNDEF && imginfo->tmar != UNDEF) {
	maxheight = info.paperheight - imginfo->bmar - imginfo->tmar;
      }
      if (maxwidth == UNDEF && maxheight == UNDEF) {
	maxwidth = max(info.paperwidth - 144, info.paperwidth * 0.75);
	maxheight = max(info.paperheight - 144, info.paperheight * 0.75);
      }
      
      rotate_dim(info.angle, imginfo->pixwidth, imginfo->pixheight * info.stretch, &r);
      
      sc = min(maxwidth == UNDEF ? INFTY : maxwidth / r.bb[0], maxheight == UNDEF ? INFTY : maxheight / r.bb[1]);
      imginfo->width = imginfo->pixwidth * sc;
      imginfo->height = imginfo->pixheight * info.stretch * sc;

    } else if (info.backend->pixel) {

      /* in pixel-based backends, assume default scaling factor of 1 */

      imginfo->width = imginfo->pixwidth;
      imginfo->height = imginfo->pixheight * info.stretch;
    } else {

      /* otherwise, choose a default size based on the default paper format */

      maxwidth = max(info.paperwidth - 144, info.paperwidth * 0.75);
      maxheight = max(info.paperheight - 144, info.paperheight * 0.75);
      
      sc = min(maxwidth / imginfo->pixwidth, maxheight / imginfo->pixheight / info.stretch);
      imginfo->width = imginfo->pixwidth * sc;
      imginfo->height = imginfo->pixheight * info.stretch * sc;
    }
  }

  /* calculate coordinate system */
  rotate_dim(info.angle, imginfo->width, imginfo->height, &imginfo->trans);

  /* adjust margins */
  if (info.backend->fixed) {
    if (imginfo->lmar == UNDEF && imginfo->rmar == UNDEF) {
      imginfo->lmar = (info.paperwidth-imginfo->trans.bb[0])/2;
    } else if (imginfo->lmar == UNDEF) {
      imginfo->lmar = (info.paperwidth-imginfo->trans.bb[0]-imginfo->rmar);
    } else if (imginfo->lmar != UNDEF && imginfo->rmar != UNDEF) {
      imginfo->lmar += (info.paperwidth-imginfo->trans.bb[0]-imginfo->lmar-imginfo->rmar)/2;
    }
    if (imginfo->bmar == UNDEF && imginfo->tmar == UNDEF) {
      imginfo->bmar = (info.paperheight-imginfo->trans.bb[1])/2;
    } else if (imginfo->bmar == UNDEF) {
      imginfo->bmar = (info.paperheight-imginfo->trans.bb[1]-imginfo->tmar);
    } else if (imginfo->bmar != UNDEF && imginfo->tmar != UNDEF) {
      imginfo->bmar += (info.paperheight-imginfo->trans.bb[1]-imginfo->bmar-imginfo->tmar)/2;
    }
  } else {
    if (imginfo->lmar == UNDEF) {
      imginfo->lmar = 0;
    }
    if (imginfo->rmar == UNDEF) {
      imginfo->rmar = 0;
    }
    if (imginfo->bmar == UNDEF) {
      imginfo->bmar = 0;
    }
    if (imginfo->tmar == UNDEF) {
      imginfo->tmar = 0;
    }
  }
}

/* ---------------------------------------------------------------------- */
/* auxiliary functions for file handling */

/* open a file for reading. Return stdin if filename is NULL or "-" */ 
static FILE *my_fopen_read(char *filename) {
  if (filename == NULL || strcmp(filename, "-") == 0) {
    return stdin;
  }
  return fopen(filename, "rb");
}

/* open a file for writing. Return stdout if filename is NULL or "-" */ 
static FILE *my_fopen_write(char *filename) {
  if (filename == NULL || strcmp(filename, "-") == 0) {
    return stdout;
  }
  return fopen(filename, "wb");
}

/* close a file, but do nothing is filename is NULL or "-" */
static void my_fclose(FILE *f, char *filename) {
  if (filename == NULL || strcmp(filename, "-") == 0) {
    return;
  }
  fclose(f);
}

/* make output filename from input filename. Return an allocated value. */
static char *make_outfilename(char *infile, char *ext) {
  char *outfile;
  char *p;

  if (strcmp(infile, "-") == 0) {
    return strdup("-");
  }

  outfile = (char *) malloc(strlen(infile)+strlen(ext)+5);
  if (!outfile) {
    return NULL;
  }
  strcpy(outfile, infile);
  p = strrchr(outfile, '.');
  if (p) {
    *p = 0;
  }
  strcat(outfile, ext);

  /* check that input and output filenames are different */
  if (strcmp(infile, outfile) == 0) {
    strcpy(outfile, infile);
    strcat(outfile, "-out");
  }

  return outfile;
}

/* ---------------------------------------------------------------------- */
/* Process one infile */

/* Process one or more bitmaps from fin, and write the results to fout
   using the page_f function of the appropriate backend. */

static void process_file(backend_t *b, const char *infile, const char *outfile, FILE *fin, FILE *fout) { 
  int r; 
  potrace_bitmap_t *bm = NULL; 
  imginfo_t imginfo;
  int eof_flag = 0;  /* to indicate premature eof */
  int count;         /* number of bitmaps successfully processed, this file */
  potrace_state_t *st;
  simple_progress_t progress_data;

  for (count=0; ; count++) {
    /* read a bitmap */
    r = bm_read(fin, info.blacklevel, &bm);
    switch (r) {
    case -1:  /* system error */
      fprintf(stderr, ""POTRACE": %s: %s\n", infile, strerror(errno));
      exit(2);
    case -2:  /* corrupt file format */
      fprintf(stderr, ""POTRACE": %s: file format error: %s\n", infile, bm_read_error);
      exit(2);
    case -3:  /* empty file */
      if (count>0) {  /* end of file */
	return;
      }
      fprintf(stderr, ""POTRACE": %s: empty file\n", infile);
      exit(2);
    case -4:  /* wrong magic */
      if (count>0) { 
	fprintf(stderr, ""POTRACE": %s: warning: junk at end of file\n", infile);
	return;
      }
      fprintf(stderr, ""POTRACE": %s: file format not recognized\n", infile);
      fprintf(stderr, "Possible input file formats are: pnm (pbm, pgm, ppm), bmp.\n");
      exit(2);
    case 1:  /* unexpected end of file */
      fprintf(stderr, ""POTRACE": warning: %s: premature end of file\n", infile);
      eof_flag = 1;
      break;
    }

    /* prepare progress bar, if requested */
    if (info.progress) {
      init_progress(&info.param->progress, &progress_data, infile, count);
    } else {
      info.param->progress.callback = NULL;
    }

    if (info.invert) {
      bm_invert(bm);
    }

    /* process the image */
    st = potrace_trace(info.param, bm);
    if (!st || st->status != POTRACE_STATUS_OK) {
      fprintf(stderr, ""POTRACE": %s: %s\n", infile, strerror(errno));
      exit(2);
    }

    /* calculate image dimensions */
    imginfo.pixwidth = bm->w;
    imginfo.pixheight = bm->h;
    calc_dimensions(&imginfo);

    bm_free(bm);

    r = b->page_f(fout, st->plist, &imginfo);
    if (r) {
      fprintf(stderr, ""POTRACE": %s: %s\n", outfile, strerror(errno));
      exit(2);
    }

    potrace_state_free(st);

    if (info.progress) {
      fprintf(stderr, "\n");
    }

    if (eof_flag || !b->multi) {
      return;
    }
  }
  /* not reached */
}

/* ---------------------------------------------------------------------- */
/* main: handle file i/o */

#define TRY(x) if (x) goto try_error

int main(int ac, char *av[]) {
  backend_t *b;  /* backend info */
  FILE *fin, *fout;
  int i;
  char *outfile;

  /* platform-specific initializations, e.g., set file i/o to binary */
  platform_init();

  /* process options */
  dopts(ac, av);

  b = info.backend;
  if (b==NULL) {
    fprintf(stderr, ""POTRACE": internal error: selected backend not found\n");
    exit(1);
  }

  /* fix some parameters */
  /* if backend cannot handle opticurve, disable it */
  if (b->opticurve == 0) {
    info.param->opticurve = 0;
  }

  /* there are several ways to call us:
     potrace                     -- stdin to stdout
     potrace -o outfile          -- stdin to outfile
     potrace file...             -- encode each file and generate outfile names
     potrace -o outfile file...  -- concatenate files and write to outfile

     The latter form is only allowed one file for single-page
     backends.  For multi-page backends, each file must contain 0 or
     more complete bitmaps.
  */

  if (info.infilecount == 0) {                 /* read from stdin */

    fout = my_fopen_write(info.outfile);
    if (!fout) {
      fprintf(stderr, ""POTRACE": %s: %s\n", info.outfile ? info.outfile : "stdout", strerror(errno));
      exit(2); 
    }
    if (b->init_f) {
      TRY(b->init_f(fout));
    }
    process_file(b, "stdin", info.outfile ? info.outfile : "stdout", stdin, fout);
    if (b->term_f) {
      TRY(b->term_f(fout));
    }
    my_fclose(fout, info.outfile);
    return 0;

  } else if (!info.outfile) {                /* infiles -> multiple outfiles */

    for (i=0; i<info.infilecount; i++) {
      outfile = make_outfilename(info.infiles[i], b->ext);
      if (!outfile) {
	fprintf(stderr, ""POTRACE": %s\n", strerror(errno));
	exit(2);
      }
      fin = my_fopen_read(info.infiles[i]);
      if (!fin) {
	fprintf(stderr, ""POTRACE": %s: %s\n", info.infiles[i], strerror(errno));
	exit(2);
      }
      fout = my_fopen_write(outfile);
      if (!fout) {
	fprintf(stderr, ""POTRACE": %s: %s\n", outfile, strerror(errno));
	exit(2);
      }
      if (b->init_f) {
	TRY(b->init_f(fout));
      }
      process_file(b, info.infiles[i], outfile, fin, fout);
      if (b->term_f) {
	TRY(b->term_f(fout));
      }
      my_fclose(fin, info.infiles[i]);
      my_fclose(fout, outfile);
      free(outfile);
    }
    return 0; 

  } else {                                   /* infiles to outfile */

    if (!b->multi && info.infilecount >= 2) {
      fprintf(stderr, ""POTRACE": cannot use multiple input files with -o in %s mode\n", b->name);
      exit(1);
    }
    
    fout = my_fopen_write(info.outfile);
    if (!fout) {
      fprintf(stderr, ""POTRACE": %s: %s\n", info.outfile, strerror(errno));
      exit(2);
    }
    if (b->init_f) {
      TRY(b->init_f(fout));
    }
    for (i=0; i<info.infilecount; i++) {
      fin = my_fopen_read(info.infiles[i]);
      if (!fin) {
	fprintf(stderr, ""POTRACE": %s: %s\n", info.infiles[i], strerror(errno));
	exit(2);
      }
      process_file(b, info.infiles[i], info.outfile, fin, fout);
      my_fclose(fin, info.infiles[i]);
    }
    if (b->term_f) {
      TRY(b->term_f(fout));
    }
    my_fclose(fout, info.outfile);
    return 0;

  }

  /* not reached */

 try_error:
  fprintf(stderr, ""POTRACE": %s\n", strerror(errno));
  exit(2);
}
