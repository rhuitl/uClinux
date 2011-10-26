/* Analyse der Fax-Logdatei: Liste aller ausgehenden erfolgreichen */
/* Verbindungen mit Dauer und Kosten. */
/* Das optionale erste Argument gibt die Dauer einer Telefoneinheit an */
/* 24.11.94 Roland Meier */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define STRSIZ 100


int main(int argc, char *argv[])
{
  FILE *fin;
  char *ptr;
  char str[STRSIZ],id[STRSIZ];
  double einheit=0, gpreis=0;
  int amon,atag,astd,amin,asek;
  int bmon,btag,bstd,bmin,bsek;
  int anz, stat, geschw=0, ende=0, endeerk=1;

  if (argc>1) {
    einheit = atoi(argv[1]);
    if ((!einheit) || (argc>2)) {
      fprintf(stderr,"usage: %s [Dauer einer Einheit]\n\n", argv[0]);
      exit(1);
    }
  }     
  if (!einheit)
    einheit = 360;
  if ( !(fin=fopen("/var/spool/fax/Faxlog","r"))) {
    fprintf(stderr,"Logdatei nicht gefunden!\n\n");
    exit(2);
  }
  printf("Dauer einer Telefoneinheit: %1.0f Sekunden\n", einheit);
  printf("empfangene ID\t\tDatum\t\tSeiten Dauer Kosten Geschw. OK=0\n");
  while (fgets(str,STRSIZ,fin)) {
    if (strstr(str,"+FCON")) {
      sscanf(str,"%d/%d %d:%d:%d",
	     &amon, &atag, &astd, &amin, &asek);
      if (!endeerk)
	fprintf(stderr, "Fehler: FCON ohne vorheriges hangup!\n");
      endeerk=0;		/* Flag Ende erkannt */
    }
    else if ((ptr=strstr(str,"fax_id: '+FCSI: "))) {
      strcpy(id,ptr+17);
      id[strlen(id)-3]=0;
    }
    else if ((ptr=strstr(str,"checking f"))) {
      sscanf(ptr+10,"%d", &anz);
    }
    else if ((ptr=strstr(str,"transmission par"))) {
      sscanf(ptr+29, "%d", &geschw);
    }
    else if (!endeerk && (ptr=strstr(str,"hangup: '+FHNG:"))) {
      sscanf(str,"%d/%d %d:%d:%d", &bmon, &btag, &bstd, &bmin, &bsek);
      sscanf(ptr+16, "%d", &stat);
      ende=endeerk=1;
    }
    else if (!endeerk && strstr(str,"##### failed transmitting")) {
      sscanf(str,"%d/%d %d:%d:%d",
	     &bmon, &btag, &bstd, &bmin, &bsek);
      ptr=strstr(str,"+FHS:");
      sscanf(ptr+5, "%d", &stat);
      ende=endeerk=1;
    }
    if (ende) {
      double preis;
      int atime, btime;

      if (amon != bmon) {	/* ich gehe mal vom naechsten Monat aus... */
	  switch (amon) {
	  case 1:
	  case 3:
	  case 5:
	  case 7:
	  case 8:
	  case 10:
	  case 12:
	    btag += 31;
	    break;
	  default:
	    btag += 30;
	  }
	}
      atime = atag*24*3600+astd*3600+amin*60+asek;
      btime = btag*24*3600+bstd*3600+bmin*60+bsek;
      preis = ceil((btime-atime)/einheit)*0.23;
      gpreis += preis;
      printf("%s\t%2d.%2d %2d:%2d:%2d\t%2d S,%3d Sek,%5.2f DM, G.%d,St %d\n",
	     id, atag,amon,astd,amin,asek,
#if 0
	     btag,bmon,bstd,bmin,bsek,
\t%2d.%2d %2d:%2d:%2d
#endif
	     anz, btime-atime, preis, geschw, stat);
      ende=anz=geschw=0;	/* falls Fehler beim naechsten Mal */
      strcpy(id,"(FEHLER!)           ");
    }
  }
  printf("Gesamtkosten: %1.2f DM\n", gpreis);
  fclose(fin);
  return(0);
}

