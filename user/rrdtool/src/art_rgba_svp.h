#ifndef SP_ART_RGBA_SVP_H
#define SP_ART_RGBA_SVP_H

#ifndef ENABLE_GIF
#include <libart_lgpl/art_misc.h>
#include <libart_lgpl/art_alphagamma.h>
#include <libart_lgpl/art_affine.h>
#include <libart_lgpl/art_svp.h>
#include <libart_lgpl/art_uta.h>

void
gnome_print_art_rgba_svp_alpha (const ArtSVP *svp,
				int x0, int y0, int x1, int y1,
				art_u32 rgba,
				art_u8 *buf, int rowstride,
				ArtAlphaGamma *alphagamma);
#endif /* ENABLE_GIF */

#endif /* SP_ART_RGBA_SVP_H */
