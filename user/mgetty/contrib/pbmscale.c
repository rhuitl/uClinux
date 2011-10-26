/* pbmscale.c - scale a portable bitmap
**
** Copyright (C) 1989 by Paul Haeberli <paul@manray.sgi.com>.
** Copyright (C) 1993 by Chel van Gennip <chel@bazis.nl>
**
** Permission to use, copy, modify, and distribute this software and its
** documentation for any purpose and without fee is hereby granted, provided
** that the above copyright notice appear in all copies and that both that
** copyright notice and this permission notice appear in supporting
** documentation.  This software is provided "as is" without express or
** implied warranty.
**
** Update jun 11,1993, Chel van Gennip,
**   added simple scaling to improve speed 
**
*/

#include "pbm.h"

void main( argc, argv )
int argc;
char *argv[];
    {
    FILE *ifp;
    int argn, rows, wrows, cols, wcols, row, wrow, col, wcol, i,format;
    int vval,vscale,hval,hscale;
    bit *readrow, *writerow, *bP, *wbP,bitval;
    float aspect,scale;
    char *usage = "[-scale N] [-aspect N] [-stretch] [pbmfile]";

    pbm_init( &argc, argv );

    argn = 1;
    aspect=1.0;
    scale=1.0;

    /* Check for flags. */
    while ( argn < argc && argv[argn][0] == '-' && argv[argn][1] != '\0' )
    {
    if ( pm_keymatch( argv[argn], "-stretch", 2 ) )
        aspect=2.0;
        else if ( pm_keymatch( argv[argn], "-aspect", 2 ) )
            {
            ++argn;
            if ( argn == argc || sscanf( argv[argn], "%f", &aspect ) != 1 )
                pm_usage( usage );
            }
        else if ( pm_keymatch( argv[argn], "-scale", 2 ) )
            {
            ++argn;
            if ( argn == argc || sscanf( argv[argn], "%f", &scale ) != 1 )
                pm_usage( usage );
            }
    else
        pm_usage( usage );
    argn++;
    }

    if ( argn < argc )
    {
    ifp = pm_openr( argv[argn] );
    argn++;
    }
    else
    ifp = stdin;

    if ( argn != argc )
    pm_usage( usage );

    vscale=aspect*scale*100;
    hscale=scale*100;

    pbm_readpbminit( ifp, &cols, &rows, &format );
    readrow= pbm_allocrow( cols );
    wcols=(cols*hscale)/100;
    wrows=(rows*vscale)/100;
    writerow= pbm_allocrow( wcols );
    pbm_writepbminit( stdout, wcols, wrows, 0 );
    vval=wrow=row=0;
    while(row<rows){
      for ( col = 0, bP = writerow; col < wcols; ++col, ++bP )
            *bP = PBM_WHITE;
      while (vval<100){
        if(row<rows){
          hval=wcol=col=0;
          pbm_readpbmrow( ifp, readrow, cols, format );
          bP=readrow;
          wbP=writerow;
          while(col<cols){
            bitval = *wbP;
            while(hval<100){
              if(col++<cols)
                if( *bP++ == PBM_BLACK)
                  bitval=PBM_BLACK ;
              hval+=hscale;
            }
            while(hval>=100){
              if(wcol++<wcols)*wbP++=bitval;
              hval -= 100;
            }
          } /* while(col */
        } /* if(row */
        vval+=vscale;
        row++;
      } /* while vval */
      while (vval>=100){
        if(wrow<wrows){
          pbm_writepbmrow( stdout, writerow, wcols, 0 );
          wrow++;
        }
        vval -= 100;
      }         
    }
    for ( row = wrow; row < wrows; ++row )
    pbm_writepbmrow( stdout, writerow, wcols, 0 );

    exit(0);
    }
==========================================================================

+-----------------------------------------------+
| signature of: Chel van Gennip                 |
+-----------------------------------------------+
| BAZIS                                         |
| Centrale Ontwikkeling- en Ondersteuningsgroep |
| Ziekenhuis Informatie Systeem                 |
| afdeling Systeemgroep                         |
+-----------------------------------------------+
| Schipholweg 97             tel: +31-71-256762 |
| 2316 AX Leiden             fax: +31-71-216675 |
| the Netherlands                               |
+-----------------------------------------------+

