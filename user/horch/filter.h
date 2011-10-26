

#define TRUE       1
#define FALSE      0

#define MAX_RANGE  50       // Maximale Anzahl von Filter-Bereichen
#define RANGE_MIN  0        // Minimaler Wert für eine Bereichsgrenze
#define MAX_UINT   0xFFFF   // Maximaler Wert für eine Bereichsgrenze
#define RANGE_MAX  0x1FFFFFFF    // Maximaler Wert für eine Message ID des
			// Signalgenerators (0X1FFFFFFF ist der größte für
			// random(RANGE_MAX) zulässige Wert

#define MAX_LEN_PARA_STRING 256  // Zulässige Länge eines Parameterstrings
#define ERROR_FILTERPARAMETER "\n\rFilterparameter fehlerhaft!\n\r"


extern int debug;	/* global debug flag */


void f_array_h(void);           // Ausgabe Filterarray
int filter(unsigned int id);    // Filterroutine
int read_fp_string(char *fp_string);  // Routine zur Auswertung des Parameter-
				// strings -f...
void u_char_cpy(char *res,char *sc,char seek_char);    // Stringroutine

