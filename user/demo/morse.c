#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#include "../../modules/io/sgio.h"

/* Which SGIO LED are we using? counting from zero */
#define MORSE_NUM	2


/* Define the time quanta we'll be using.  This is the length of a dot.
 * A dash is triple this and the gap between dots and dashes is the same
 * as this.  The gap between words is seven units and the gap between letters
 * is three units.  The time is in microseconds.
 *
 * In addition we introduce a jitter effect which represents a variation
 * in the length of the time quanta.  This alteration can be both positive
 * and negative and only the half range is specified here.
 */
#define RATE		(1000 * 100)
#define JITTER		(RATE / 100)


/* Define our Morse alphabeta.  The first character in the string is the
 * symbol being encoded and the remainder is the morse representation as
 * dots and dashes.
 */
const char *morse_code[] = {
	"a.-", "b-...", "c-.-.", "d-..", "e.", "f..-.", "g--.", "h....", "i..",
	"j.---", "k-.-", "l.-..", "m--", "n-.", "o---", "p.--.", "q--.-",
	"r.-.", "s...", "t-", "u..-", "v...-", "w.--", "x-..-", "y-.--",
	"z--..", "1.----", "2..---", "3...--", "4....-", "5.....", "6-....",
	"7--...", "8---..", "9----.", "0-----", "..-.-.-", ",--..--",
	"?..--..", "--....-", "=-...-", ":---...", ";-.-.-.",
	"(-.--.", ")-.--.-", "/-..-.", "\".-..-.", "$...-..-", "'.----.",
	"\n.-.-..", ".-.-..", "_..--.-",
	"+.-.-.", "!...-.-", "\030........",
	NULL
};


/* This is the message we produce
 */
const char *msg =
	"sos i've been kidnapped and forced to run this demonstration.";


/* Provide a gap of n units with jitter.
 */
static void gap(int n) {
	long r;
	
	r = (random() % (2 * JITTER)) - JITTER;
	usleep((r + RATE) * n);
}


/* Turn the output on
 */
static void on(int fd) {
	struct sgio_write_output_s z;

	z.number = MORSE_NUM;
	z.value = 1;
	ioctl(fd, SGIO_WRITE_OUTPUT, &z);
}


/* Turn the output off
 */
static void off(int fd) {
	struct sgio_write_output_s z;

	z.number = MORSE_NUM;
	z.value = 0;
	ioctl(fd, SGIO_WRITE_OUTPUT, &z);
}


/* Speak a Morse character.  We only handle dots and dashes here.
 */
static inline void speak(int fd, const char *code) {
	int first = 1;
	while (*code != '\0') {
		if (!first)
			gap(1);
		else
			first = 0;
		on(fd);
		gap(*code == '.'?1:3);
		off(fd);
		code++;
	}
}


/* The main driver breaks the input characters up and speaks them.
 * We loop forever repeating the same forlorn message ad nausium.
 */
int main(int argc, char *argv[]) {
	int fd, i, j;
	unsigned int r;
	int c;
	int first = 1;
	
	srandom(time(NULL));
	fd = open("/dev/sgio", O_RDONLY);
	if (fd >= 0) {
		off(fd);
		for (;;) {
			sleep(5);
			for (i=0; msg[i] != '\0'; i++) {
				if (msg[i] == ' ') {
					gap(7);
					first = 1;
					continue;
				}
				if (!first)
					gap(3);
				else
					first = 0;
				for (j=0; morse_code[j] != NULL; j++)
					if (morse_code[j][0] == msg[i]) {
						speak(fd, morse_code[j]+1);
						break;
					}
			}
		}
	}
	fprintf(stderr, "cannot open %s\n", "/dev/sgio");
	return 1;
}
