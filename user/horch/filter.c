
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "filter.h"

int test_mod_para_str;       // Steuerparameter f¸r Anzeigen zur Pr¸fung der
			// Zerlegung des Parameterstrings
			// 0: keine Anzeige
			// 1: Anzeige der ermittelten Bereiche
			// 2: Anzeige aller verwendeten Teilsstrings
 
int test_mod_range_ar;       // Steuerparameter f¸r Anzeigen zur Pr¸fung des
			// Sortierens des Filterarrays und der Zusammenfassung
			// ¸berlappender Filterbereiche
			// 0: keine Anzeige
			// 1: Anzeige aller Schritte zur Zusammenfassung von
			//    Filterbereichen
			// 2: wie 1 + Anzeige des Filterarrays vor und
			//    nach dem Sortieren

int test_mod_filter;         // Steuerparameter f¸r Anzeigen zur Pr¸fung des
				// Filteralgorithmus
				// 0: keine Anzeige
				// 1: Anzeige aller Vergleiche

static int n_range = 0; // Anzahl der g¸ltigen Filterbereiche im Filterarray
			// n_range >= 0
			// n_range = -1  Inhalt des Filterarrays ung¸ltig

typedef struct              // Definition Filterbereich
  {
	unsigned int min;        // Untergrenze eines Durchlaﬂbereiches
	unsigned int max;        // Obergrenze eines Durchlaﬂbereiches
  } TM_Range;

/* Filterarray, default first area = all messages */ 
static TM_Range r_array[MAX_RANGE] = { { RANGE_MIN, RANGE_MAX} };



				// Nimmt maximal MAX_RANGE Durchlaﬂbereiche auf

//**************************************************************************//
// Prozedur....:  a_char_cpy                                                //
// Parameter...:  char *sc       Zeichenkette (Quelle)                      //
//                char *res      Zeichenkette (Ergebnis)                    //
//	 	  char seek_char Zeichen                                    //
// Beschreibung:  Die Prozedur sucht das Zeichen seek_char in der           //
//                Zeichenkette sc. Alle dem Zeichen seek_char folgenden     //
//                Zeichen werden in die Zeichenkette res kopiert.           //
//                Ist das Zeichen seek_char nicht in der Zeichenkette sc    //
//                entalten, dann ist die Zeichenkette res leer              //
//                Die Zeichenkette res wir mit dem Nullzeichen '\0'         //
//                abgeschlossen.                                            //
//**************************************************************************//

void a_char_cpy(char *res, char *sc, char seek_char)
{
 int Indexsc, Indexres,copy;
 Indexsc = 0;
 Indexres = 0;
 copy = FALSE;
 while (sc[Indexsc] != 0)
	{
	if (copy == TRUE)
	 { res[Indexres] =  sc[Indexsc];
		Indexres++;
	 } // if (copy == TRUE)

	if (sc[Indexsc] == seek_char) copy = TRUE;
	Indexsc++;
	} // while (sc[Indexsc] != 0)
 res[Indexres] = 0;

} // void a_char_cpy(char *res, char *sc, char seek_char)

//**************************************************************************//
// Prozedur....:  filter                                                    //
// Parameter...:  unsigned int id      Filterinput (Message ID)             //
// Beschreibung.: Das Programm pr¸ft, ob der Filterinput id innerhalb eines //
//                der im Feld r_array[i] gespeicherten Durchlaﬂbereiche     //
//                liegt:                                                    //
//                                                                          //
//                 r_array[i].min <= id <= r_array[i].max                   //
//                 0 <= i <= n_range                                        //
//                                                                          //
//                Ist die angegebene Bedingung erf¸llt gibt die Prozedur    //
//                TRUE sonst FALSE zur¸ck.                                  //
//                Die globale Variable n_range muﬂ die Bedingung            //
//                                                                          //
//                0 <= i <= n_range                                         //
//                                                                          //
//                erf¸llen. Die Prozedur ¸berpr¸ft diese nicht.             //
//                F¸r die Durchf¸hrung des Filteralgorithmus m¸ssen f¸r das //
//                globale Feld r_array[i] folgende Bedingungen gelten:      //
//                                                                          //
//                    r_array[i].min <= r_array[i].max         und          //
//                    r_array[i].min < r_array[i+1].min        und          //
//	                   r_array[i].max < r_array[i+1].min-1              //
//                    f¸r 0 <= i <= n_range-1                               //
//                                                                          //
// R¸ckgabewert.: TRUE:  Filteroutput id ist zul‰ssig                       //
//                FALSE: Filteroutput id ist unzul‰ssig                     //
//**************************************************************************//

int filter(unsigned int id)
{
int k;                        // Laufvaraiable
k = 0;
#ifdef DEBUGCODE
    if(test_mod_filter > 0) printf("\n");
#endif
    while ( k <= n_range) {
	if (id > r_array[k].max)
	  {
#ifdef DEBUGCODE
		if(test_mod_filter > 0) {
		printf(
		"Filter: ID groesser Bereich %3d  ID:%5u RMAX:  %5u\n",
		k,id,r_array[k].max);
		}
#endif
		k++;
	  } // if (id > r_array[k].max)
	 else
	  {
		if (id < r_array[k].min)
		  {
#ifdef DEBUGCODE
			if(test_mod_filter > 0) {
			printf(
			"Filter: ID kleiner Bereich  %3d  ID:%5u RMIN:  %5u\n",
			k,id,r_array[k].min);
			}
#endif
			return (FALSE);
		  } // if (id < r_array[k].min)
		 else
		  {
#ifdef DEBUGCODE
			if(test_mod_filter > 0) {
			printf("Filter: ID im Bereich       %3d  ID:%5u RANGE: %5u...%5u\n",
			k,id,r_array[k].min,r_array[k].max);
			}
#endif
			return (TRUE);
		  } // else --> if (id < r_array[k].min)
	  } // else --> if (id > r_array[k].max)
  } // while ( k <= n_range)
 return (FALSE);

} // int filter(unsigned int id)

//**************************************************************************//
// Prozedur....:  u_char_cpy                                                //
// Parameter...:  char *sc       Zeichenkette (Quelle)                      //
//                char *res      Zeichenkette (Ergebnis)                    //
//		  char seek_char Zeichen                                    //
// Beschreibung:  Die Prozedur kopiert solange Zeichen aus der Zeichenkette //
//                sc in die Zeichenkette res bis Sie das Zeichen seek_char  //
//                findet. Das Zeichen seek_char wird nicht in die Zeichen-  //
//                kette res kopiert. Wird das Zeichen seek_char nicht       //
//                gefunden, so wird die Zeichenkette sc vollst‰ndig in die  //
//                Zeichenkette res kopiert. Die Zeichenkette res wird mit   //
//                dem Nullzeichen '\0' abgeschlossen.                       //
//**************************************************************************//

void u_char_cpy(char *res,char *sc,char seek_char)
{
 int Indexsc, Indexres,notready;
 Indexsc = 0;
 Indexres = 0;
 notready = TRUE;
 while ((sc[Indexsc] != 0)&& (notready == TRUE))
	{
	if (sc[Indexsc] != seek_char)
	 {
		res[Indexres] =  sc[Indexsc];
		Indexres++;
		notready = TRUE;
	 }  // if (sc[Indexsc] != seek_char)
	else notready = FALSE;
	Indexsc++;
	} // while ((sc[Indexsc] != 0)&& (notready == TRUE))
 res[Indexres] = 0;

} // void u_char_cpy(char *res,char *sc,char seek_char)

//**************************************************************************//
// Prozedur....:  read_fp_string                                            //
// Parameter...:  char *fp_string auszuwertender Parameterstring            //
// Beschreibung.: Das Programm zerlegt einen Filterparameterstring -f...    //
//                mit dem Aufbau:                                           //
//                                                                          //
//                 -fa-b[,c-d][,-e][,g-][, ...][, ...]                      //
//                                                                          //
//                  a,b,d,c,d,g Zahlen in dezimaler oder/und hexadezimaler  //
//                  Form ( untere - obere Durchlaﬂbereichsgrenze).          //
//                Die ermittelten Durchlaﬂbereiche des Filters werden in das//
//                global g¸ltige Feld r_array[i]	                    //
//                  r_array[i].min   Untere Grenze des Durchlaﬂbereichs     //
//                  r_array[i].max   Obere Grenze des Durchlaﬂbereiches     //
//                eingetragen.                                              //
//                In der globalen Variablen n_range wird die (Anzahl-1)     //
//                der g¸ltigen Eintr‰ge im Feld r_array[0] gespeichert.     //
//                Die Prozedur realisiert folgende Aufgaben:                //
//                  - Pr¸fung des Parameterstrings -f...                    //
//                  - Zerlegung des Parameterstrings in Bereichsstrings     //
//                  - Ermittlung der unteren und oberen Bereichsgrenze      //
//                    Die Zahlenwerte im Parameterstring kˆnnen als         //
//                    Dezimalzahlen z.B. 345-490, als Hexadezimalzahlen     //
//                    z.B. 0x34-0x45 und auch gemischt angegeben werden     //
//                    z.B. 0x34-120 sein.                                   //
//                  - Ist ein String nicht konvertierbar, wird die Prozedur //
//                    mit R¸ckgabe von "FALSE" beendet.                     //
//                  - Eintrag der ermittelten Bereiche in das Feld          //
//                    r_array[i] (r_array[i].min <= r_array[i].max wird     //
//                    gesichert).                                           //
//                  - Sortieren des Feldes r_array[i] so das gilt:          //
//                    r_array[i].min <= r_array[i+1].min                    //
//                    f¸r 0 <= i <= n_range-1                               //
//                  - Zusammenfassung von ¸berlappenden Bereichen, so das   //
//                    am Ende der Prozedur gilt:                            //
//                    r_array[i].min < r_array[i+1].min        und          //
//	                   r_array[i].max < r_array[i+1].min-1              //
//                    f¸r 0 <= i <= n_range-1                               //
// R¸ckgabewert.: TRUE:  Parameterstring wurde erfolgreich konvertiert      //
//                FALSE: Parameterstring ist nicht korrekt                  //
//               ƒndert ¸bergebenen Format String !
//**************************************************************************//

int read_fp_string(char *fp_string)
{
 char range_string[MAX_LEN_PARA_STRING+1];  // enth‰lt Bereichsstring
 char value_string[MAX_LEN_PARA_STRING+1];  // enth‰lt Zahlenstring f¸r Bereichsgrenzen
					    // des Parameterstrings -f...
 char string[MAX_LEN_PARA_STRING+1];        // Zwischenergebnisse
 unsigned long min;                         // untere Grenze eines Durchlaﬂbereiches
 unsigned long max;                         // uobere Grenze eines Durchlaﬂbereiches
 unsigned int ui_min;                       // untere Grenze eines Durchlaﬂbereiches
 unsigned int ui_max;                       // obere Grenze eines Durchlaﬂbereiches
 int i,k;                                   // Laufvariable
 int ready;                                 // TRUE Algorithmus fertig
 int no_min;                                // TRUE keine untere Grenze f¸r
														  // Durchlaﬂbereich im Bereichsstring
 // Initialisierung n_range
 // Wenn n_range < 0 dann sind alle Werte im Feld r_array[MAX_RANGE] ung¸ltig!
 n_range = -1;
#ifdef DEBUGCODE
 if ((test_mod_para_str > 0) || (test_mod_range_ar > 0))
	{
	 /* keyhit(); */
	 printf("\n\rZerlegung Parameterstring fuer Filter (-f...)\n\r");
	 printf("=============================================\n\r");
	} // if ((test_mod_para_str > 0) || (test_mod_range_ar > 0))
#endif
 // Pr¸fung Parameterstring auf zul‰ssige L‰nge
 if (strlen(fp_string) > MAX_LEN_PARA_STRING)
	{
#ifdef DEBUGCODE
	 printf("\n\rFilterparameter ist zu lang (maximal %d Zeichen)!\n\r",
			  MAX_LEN_PARA_STRING);
#endif
	 return (FALSE);
	} // if (strlen(fp_string) > MAX_LEN_PARA_STRING)

 if (strlen(fp_string) < 1)
  {
#ifdef DEBUGCODE
	if(debug) {
	    printf(ERROR_FILTERPARAMETER);
	}
#endif
	return (FALSE);
  } // if (strlen(fp_string) < 1)

 /* strcpy(rest_string, fp_string); */
 while (strlen(fp_string) > 0)
  {
#ifdef DEBUGCODE
	if (test_mod_para_str > 1) {
	    printf("\n\rReststring:          %s\n\r", fp_string);
	}
#endif
	// Lese Bereichsstring
	u_char_cpy(range_string,fp_string,',');
#ifdef DEBUGCODE
	if (test_mod_para_str > 0) {
	    printf("Bereichsstring:      %s\n\r",range_string);
	}
#endif

	//Auswertung Bereichsstring
	if (strlen(range_string) > 0)
	  {
		// Lese Minimum
		no_min = FALSE;
		u_char_cpy(value_string,range_string,'-');
#ifdef DEBUGCODE
		if (test_mod_para_str > 1) {
		    printf("Wertstring Minimum:  %s\n\r",value_string);
		}
#endif
		if (strlen(value_string) == 0)
			{
			 no_min = TRUE;
			 min = 0;
			} // if (strlen(value_string) == 0)
		  else
#if 0
			{
			 if (strlen(value_string) > 6 )
				{
				 printf("\n\rWert zu lang (maximal 6 Zeichen)!");
				 return(FALSE);
				}  // if (strlen(value_string) > 6)
			 if (is_hex(value_string) == TRUE)
				{
				 min = strtol(value_string,NULL,0);
				}  // if (is_hex(value_string) == TRUE)
			  else
				{
				 if (is_number(value_string) == TRUE)
					{
					 min = atoi(value_string);
					} // if (is_number(value_string) == TRUE)
				  else
					{
					 printf(ERROR_FILTERPARAMETER);
					 return(FALSE);
					} // else --> if (is_number(value_string) == TRUE)
				} // else if (is_hex(value_string) == TRUE)
			} // else --> if (strlen(value_string) == 0)
#else
			min = strtol(value_string, NULL, 0);
#endif
#ifdef DEBUGCODE
		 if (test_mod_para_str > 0) {
		    printf("Minimum:             %lu\n\r",min);
		 }
#endif

		 // Lese Maximum
		 if (strchr(range_string,'-') == NULL)
			{
			max = min;
#ifdef DEBUGCODE
			if (test_mod_para_str > 1)  {
			    printf("Kein Trennzeichen '-'!\n\r");
			}
#endif
			} // if (strchr(range_string,'-') == NULL)
		  else
			{
			a_char_cpy(value_string,range_string,'-');
#ifdef DEBUGCODE
			if (test_mod_para_str > 1) {
			    printf("Wertstring Maximum:  %s\n\r",value_string);
			}
#endif
			 if (strlen(value_string) == 0)
				{
				 if (no_min == TRUE)
					{
#ifdef DEBUGCODE
					 printf(ERROR_FILTERPARAMETER);
#endif
					 return(FALSE);
					} // if (no_min == TRUE)
				  else
					{
					 max = MAX_UINT;
					} // else --> if (no_min == TRUE)
				} // if (strlen(value_string) == 0)
			  else
#if 0
				{
				 if (strlen(value_string) > 6)
					{
#ifdef DEBUGCODE
					 printf("\n\rWert zu lang (maximal 6 Zeichen)!");
#endif
					 return(FALSE);
					} // if (strlen(value_string) >6)
				 if (is_hex(value_string) == TRUE)
					{
					 max = strtol(value_string,NULL,0);
					} // if (is_hex(value_string) == TRUE)
				  else
					{
					 if (is_number(value_string) == TRUE)
						{
						 max = atoi(value_string);
						} // if (is_number(value_string) == TRUE)
					  else
						{
						 printf(ERROR_FILTERPARAMETER);
						 return(FALSE);
						} // else --> if (is_number(value_string) == TRUE)
					} // else --> if (is_hex(value_string) == TRUE)
				} // else --> if (strlen(value_string) == 0)
#else
			max = strtol(value_string, NULL, 0);
#endif
			} // else --> if (strchr(range_string,'-') == NULL)
#ifdef DEBUGCODE
		 if (test_mod_para_str > 0) {
		    printf("Maximum:             %lu\n\r",max);
		}
#endif
	  } // if (strlen(range_string) > 0)
	 else
	  {
		printf(ERROR_FILTERPARAMETER);
		return(FALSE);
	  } // else --> if (strlen(range_string) > 0)

	// Test Minimum und Maximum
	if (min > MAX_UINT)
	  {
		printf("\n\rWert zu gross (Minimum > %u oder 0x%X)!",0xFFFF,0xFFFF);
		return(FALSE);
	  } // if (min > MAX_UINT)
	if (max > MAX_UINT)
	  {
		printf("\n\rWert zu gross (Maximum > %u oder 0x%X)!",0xFFFF,0xFFFF);
		return(FALSE);
	  } // if (max > MAX_UINT)
	if (min > max)
	  {
		printf("\nBereichsfehler (Minimum > Maximum)!");
		return(FALSE);
	  } // if (min > max)

	//Max und Min in Bereichsfeld r_array[MAX_RANGE] eintragen
	ui_min = (unsigned int) min;
	ui_max = (unsigned int) max;
	if (n_range == -1)
	  {
		// noch kein Eintrag im Feld vorhanden
		r_array[0].min = ui_min;
		r_array[0].max = ui_max;
		n_range = 0;
	  } // if (n_range == -1)
	 else
	  {
		if (n_range < MAX_RANGE)
		  {
			n_range++;
			r_array[n_range].min = ui_min;
			r_array[n_range].max = ui_max;
		  } // if (n_range < MAX_RANGE)
		 else
		  {
			printf("\nPrameterstring enthaelt zuviele Bereiche!");
			return(FALSE);
		  } // else --> if (n_range < MAX_RANGE)
	  } // else --> if (n_range == -1)

	// Entferne ausgewerteten Bereichsstring
	strcpy(string,fp_string);
	a_char_cpy(fp_string,string,',');
#ifdef DEBUGCODE
	if (test_mod_para_str > 0) {
	    /* keyhit(); */
	}
#endif
  } // while (strlen(fp_string) > 0)

 // Sortieren und Ordnen des Feldes r_array[k]
 // Das Sortieren gew‰hrleistet, daﬂ r_array[k].min < r_array[k+1].min
 // f¸r alle 0 <= k <= n_range gilt.
 // Es d¸rfen sich keine Bereiche ¸berlappen.

#ifdef DEBUGCODE
 if (test_mod_range_ar > 1)
	 {
	  printf("\nFilterbereiche sortieren\n");
	  printf("------------------------\n");
	  f_array_h();
	  /* keyhit(); */
	 } // if (test_mod_range_ar > 1)
#endif

 if (n_range > 0)
	{
	 // Das Feld muﬂ nur dann sortiert werden, wenn mehr als ein
	 // Bereich eingetragen ist
	 // exchange sort, bubblesort
	 do
	  {
		ready = TRUE;
		for (k=0;k<n_range;k++)
			{
			 if (r_array[k].min > r_array[k+1].min)
				{
				 //  r_array[k].min > r_array[k+1].min
				 //  Pl‰tze tauschen
				 ui_min = r_array[k].min;
				 ui_max = r_array[k].max;
				 r_array[k].min = r_array[k+1].min;
				 r_array[k].max = r_array[k+1].max;
				 r_array[k+1].min = ui_min;
				 r_array[k+1].max = ui_max;
				 ready = FALSE;
				} // if (r_array[k].min > r_array[k+1].min)
			} // for (k=0;k<n_range;k++)
	  } // do
	 while (ready == FALSE);

#ifdef DEBUGCODE
	 if (test_mod_range_ar > 1) {
	     printf("\nFilterbereiche sortiert:\n");
	     f_array_h();
	     /* keyhit(); */
	 } // if (test_mod_range_ar > 1)
	 // Zusammenfasen der Bereiche
	 if (test_mod_range_ar > 0) {
	     printf("\nZusammenfassen Filterbereichen\n");
	     printf("-----------------------------\n\n");
	     f_array_h();
	 } // if (test_mod_range_ar > 0)
#endif
	 k = 0;
	 ready = FALSE;
	 while (ready == FALSE)
	  {
		if ( r_array[k+1].max > r_array[k].max)
		  {
			 // Fall 1
			 //            |---------|     Bereich  k
			 //            |..........|    Bereich  k+1
			 //            |...............|
			 //                 |.....|
			 //                 |..........|
			 //                      |.....|
			 //                       |....|
			 //                             |....|
			 if (r_array[k+1].min > (r_array[k].max + 1))
			    {
#ifdef DEBUGCODE
			     if (test_mod_range_ar > 0) {
				 printf("-->Fall 1.1 k = %d n_range= %d Bereich %d und %d sind getrennt (**fertig**)!\n", k, n_range, k, k+1);
			     }
#endif
			     // Fall 1.1
			     //            |---------|         Bereich  k
			     //                         |....| Bereich  k+1
			     k++;
			     if (k == n_range)
				    {
				     ready = TRUE;
				    } // if (k == n_range)
			    } // if (r_array[k+1].min > (r_array[k].max + 1))
			  else
			    {
#ifdef DEBUGCODE
			      if (test_mod_range_ar > 0) {
				  printf("--> Fall 1.2 k = %d n_range= %d Bereich %d und %d zusammenfassen!\n", k, n_range, k, k+1);
			      }
#endif
			      // Fall 1.2
			      //            |---------|     Bereich  k
			      //            |..........|    Bereich  k+1
			      //            |...............|
			      //                 |.....|
			      //                 |..........|
			      //                      |.....|
			      //                       |....|
			     r_array[k].max = r_array[k+1].max;
			     i = k + 1;
			     while (i < n_range)
			      {
				    r_array[i].min = r_array[i+1].min;
				    r_array[i].max = r_array[i+1].max;
				    i++;
			      } //  while (i < n_range)
			     n_range = n_range - 1;
			     k = 0;
			    } // else --> if (r_array[k+1].min > (r_array[k].max + 1))
		  } // if ( r_array[k+1].max > r_array[k].max)
		 else
		  {
#ifdef DEBUGCODE
			if (test_mod_range_ar > 0) {
			    printf("--> Fall 2   k = %d n_range= %d Bereich %d und %d zusammenfassen!\n", k, n_range, k, k+1);
			}
#endif
			 // Fall 2
			 //            |---------|     Bereich  k
			 //            |.........|     Bereich  k+1
			 //            |........|
			i = k + 1;
			while (i < n_range)
			 {
			  r_array[i].min = r_array[i+1].min;
			  r_array[i].max = r_array[i+1].max;
			  i++;
			 } // while (i < n_range)
			n_range = n_range - 1;
			k = 0;
		  } // else --> if ( r_array[k+1].max > r_array[k].max)
#ifdef DEBUGCODE
		if (test_mod_range_ar > 0) {
		    /* keyhit(); */
		    printf("Ergebnisse: \n");
		    printf("k = %d n_range= %d\n", k, n_range);
		    f_array_h();
		} // if (test_mod_range_ar > 0)
#endif
	  } // while (ready == FALSE)
	} // if (n_range > 0)


#ifdef DEBUGCODE
    f_array_h();
#endif
 return(TRUE);

 } // read_fp_string(char *fp_string)

//**************************************************************************//
// Prozedur....:  f_array_h                                                 //
// Parameter...:                                                            //
// Beschreibung:  Die Prozedur gibt das gloabale Array r_array[i] als       //
//                Tabelle aus, wenn f¸r die globale Variable n_range        //
//                    n_range > -1                                          //
//                gilt.                                                     //
//                Unabh‰ngig davon wird der Tabellenkopf                    //
//                Nummer   Minimum     Maximum                              //
//                immer ausgegeben. Die Spalten enthalten:                  //
//                Nummer:     i                                             //
//                Minimum:    r_array[i].min                                //
//                Maximum:    r_array[i].max                                //
//**************************************************************************//

void f_array_h(void)
{
 int k;
 // Ausgabe Filterbereiche
	 k = -1;
	 printf("Nummer   Minimum     Maximum\n");
	 while (k < n_range)
	  {
		k++;
		printf("%5d    %5X H      %5X H\n", k,r_array[k].min,r_array[k].max );
	  } // while (k < n_range)

} // void f_array_h(void)
