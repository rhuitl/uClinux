/*
 * font.c
 *
 * Copyright (C) 2000 Rasca, Berlin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define ERROR -1
#define DPI 76
#define TT_VALID(x) ((x).z != NULL)

typedef struct _ttfont {
	TT_Face face;
	TT_Face_Properties props;
	TT_Instance inst;
	int smooth;
} ttfont;

static unsigned char bounded_palette[8] = {0, 1, 2, 3, 4, 4, 4, 4};

/*
 */
int
Face_Open (char *file, TT_Engine engine, TT_Face *face,
			TT_Face_Properties *prop, TT_Instance *inst, int ptsize)
{
	if (TT_Open_Face (engine, file, face)) {
		return ERROR;
	}
	TT_Get_Face_Properties (*face, prop);

	TT_New_Instance (*face, inst);
	TT_Set_Instance_Resolutions (*inst, DPI, DPI);
	TT_Set_Instance_CharSize (*inst, ptsize*64);
	return 0;
}

/*
 * release the resources for the instance and the face
 */
void
Face_Done (TT_Instance inst, TT_Face face)
{
	TT_Done_Instance (inst);
	TT_Close_Face (face);
}

/*
 */
TT_Glyph *
Glyphs_Load (TT_Face face, TT_Face_Properties *prop, TT_Instance inst,
		unsigned char *str, int len)
{
	unsigned short n, i;
	unsigned short platform, encoding;
	unsigned short num_glyphs = 0, num_cmap = 0;
	unsigned short load_flags, j, code;

	TT_CharMap char_map;
	TT_Glyph *gl;

	n = prop->num_CharMaps;
	for (i = 0; i < n; i++) {
		TT_Get_CharMap_ID (face, i, &platform, &encoding);
		if ((platform == 3 && encoding == 1) ||
			(platform == 0 && encoding == 0)) {
			TT_Get_CharMap (face, i, &char_map);
			break;
		}
	}
	if (i == n) {
		num_cmap = i;
		num_glyphs = prop->num_Glyphs;
	}
	gl = (TT_Glyph *) malloc (256 * sizeof (TT_Glyph));
	memset (gl, 0, 256 * sizeof (TT_Glyph));

	load_flags = TTLOAD_SCALE_GLYPH;
	for (i = 0; i < len; i++) {
		j = str[i];
		if (TT_VALID(gl[j])) {	/* still done */
			continue;
		}
		if (num_cmap) {
			/* hmm.. does this really work? */
			code = (j - ' ' + 1) < 0 ? 0 : (j - ' ' + 1);
			if (code >= num_glyphs) {
				code = 0;
			}
		} else {
			code = TT_Char_Index (char_map, j);
		}
		TT_New_Glyph (face, &gl[j]);
		TT_Load_Glyph (inst, gl[j], code, load_flags);
	}
	return gl;
}

/*
 */
void
Glyphs_Done (TT_Glyph *gl)
{
	int i;
	if (!gl)
		return;
	for (i = 0; i < 256; i++) {
		TT_Done_Glyph (gl[i]);
	}
	free (gl);
}

/*
 */
void
Raster_Init (TT_Face face, TT_Face_Properties *prop, TT_Instance inst,
			unsigned char *str,
			int len, int border, TT_Glyph *gl, TT_Raster_Map *bit)
{
	TT_Instance_Metrics imetrics;
	int upm, ascent, descent;
	int width, height, i;
	unsigned int j;
	TT_Glyph_Metrics gmetrics;

	TT_Get_Instance_Metrics (inst, &imetrics);
	upm = prop->header->Units_Per_EM;
	ascent = (prop->horizontal->Ascender * imetrics.y_ppem) / upm;
	descent= (prop->horizontal->Descender * imetrics.y_ppem) / upm;

	width = 2 * border;
	height= 2 * border + ascent - descent;
	for (i = 0; i < len; i++) {
		j = str[i];
		if (!TT_VALID(gl[j]))
			continue;
		TT_Get_Glyph_Metrics (gl[j], &gmetrics);
		width += gmetrics.advance / 64;
	}
	bit->rows = height;
	bit->width= width;
	bit->cols= (width + 3) & -4;	 /* for pixmap, must be 32-bits aligned */
	bit->flow = TT_Flow_Down;

	bit->size = bit->rows * bit->cols;
	bit->bitmap = malloc (bit->size);
	if (bit->bitmap)
		memset (bit->bitmap, 0, bit->size);
}

/*
 */
void
Raster_Done (TT_Raster_Map *bit)
{
	free (bit->bitmap);
	bit->bitmap = NULL;
}

/*
 */
void
Raster_Small_Init (TT_Raster_Map *map, TT_Instance *inst)
{
	TT_Instance_Metrics metrics;
	TT_Get_Instance_Metrics (*inst, &metrics);
	map->rows = metrics.y_ppem + 32;
	map->width= metrics.x_ppem + 32;
	map->cols = (map->width + 3) & -4;
	map->flow = TT_Flow_Up;
	map->size = (long)map->rows * map->cols;
	map->bitmap = malloc ((int)map->size);
}

/*
 */
void
Bitmap_Clear (TT_Raster_Map *map)
{
	if (map && map->bitmap)
		memset (map->bitmap, 0, map->size);
}

/*
 */
void
Render_Glyph (TT_Glyph g, TT_Glyph_Metrics *gm, int x_offset, int y_offset,
		TT_Raster_Map *bit,
		TT_Raster_Map *sbit)
{
	TT_F26Dot6  x, y, xmin, ymin, xmax, ymax;
	int ioff, iread;
	char *off, *read, *off2, *read2;

	xmin = gm->bbox.xMin & -64;
	ymin = gm->bbox.yMin & -64;
	xmax = (gm->bbox.xMax+63) & -64;
	ymax = (gm->bbox.yMax+63) & -64;

	Bitmap_Clear (sbit);
	if (TT_Get_Glyph_Pixmap (g, sbit, -xmin, -ymin))
		return;
	xmin = (xmin >> 6) + x_offset;
	ymin = (ymin >> 6) + y_offset;
	xmax = (xmax >> 6) + x_offset;
	ymax = (ymax >> 6) + y_offset;

	if (xmin >= (int)bit->width ||
		ymin >= (int)bit->rows ||
		xmax < 0 ||
		ymax < 0)
		return;

	if (xmax - xmin + 1 > sbit->width)
		xmax = xmin + sbit->width - 1;
	if (ymax - ymin + 1 > sbit->rows)
		ymax = ymin + sbit->rows - 1;

	iread = 0;
	if (ymin < 0) {
		iread -= ymin * sbit->cols;
		ioff = 0;
		ymin = 0;
	} else {
		ioff = ymin * bit->cols;
	}

	if (ymax >= bit->rows)
		ymax = bit->rows-1;

	if (xmin < 0) {
		iread -= xmin;
		xmin = 0;
	} else {
		ioff += xmin;
	}

	if (xmax >= bit->width)
		xmax = bit->width - 1;

	read2 = (char *)sbit->bitmap + iread;
	off2  = (char *)bit->bitmap + ioff;

	for (y = ymin; y <= ymax; y++) {
		read = read2;
		off = off2;
		for (x = xmin; x <= xmax; x++) {
			*off = bounded_palette[*off | *read];
			off++;
			read++;
		}
		read2 += sbit->cols;
		off2 += bit->cols;
	}
}

/*
 */
unsigned char *
Render_String (TT_Glyph *gl, unsigned char *str, int len, TT_Raster_Map *bit,
		TT_Raster_Map *sbit, int border)
{
	int i;
	unsigned int j;
	TT_F26Dot6 x, y, z, min_x, min_y, max_x, max_y;
	TT_Glyph_Metrics gmetrics;

	min_x = min_y = 0;
	max_x = max_y = 0;
	x = 0;
	y = 0;

	for (i = 0; i < len; i++) {
		j = str[i];
		if (!TT_VALID(gl[j]))
			continue;
		TT_Get_Glyph_Metrics (gl[j], &gmetrics);

		z = x + gmetrics.bbox.xMin;
		if (min_x > z)
			min_x = z;

		z = x + gmetrics.bbox.xMax;
		if (max_x < z)
			max_x = z;

		z = y + gmetrics.bbox.yMin;
		if (min_y > z)
			min_y = z;
	
		z = y + gmetrics.bbox.yMax;
		if (max_y < z)
			max_y = z;

		x += gmetrics.advance & -64;

	}
	min_x = (min_x & -64) >> 6;
	min_y = (min_y & -64) >> 6;
	max_x = ((max_x + 63) & -64) >> 6;
	max_y = ((max_y + 63) & -64) >> 6;

	max_x -= min_x;
	max_y -= min_y;

	min_x = (bit->width - max_x + 2) / 2;
	min_y = (bit->rows - max_y + 4) / 2;

	max_x += min_x;
	max_y += min_y;


	/* */
	x = min_x;
	y = min_y;
	for (i = 0; i < len; i++) {
		j = str[i];
		if (!TT_VALID(gl[j]))
			continue;
		TT_Get_Glyph_Metrics (gl[j], &gmetrics);
		Render_Glyph (gl[j], &gmetrics, x, y, bit, sbit);
		x += gmetrics.advance / 64;
	}
	return NULL;
}

