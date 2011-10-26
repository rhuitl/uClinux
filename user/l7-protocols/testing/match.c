#include <ctype.h>
#include <stdio.h>
#include "regexp/regexp.c"

#define MAX 512
#define MAX_PATTERN_LEN 8196

static int hex2dec(char c)
{
        switch (c)
        {
                case '0' ... '9':
                        return c - '0';
                case 'a' ... 'f':
                        return c - 'a' + 10;
                case 'A' ... 'F':
                        return c - 'A' + 10;
                default:
			fprintf(stderr, "hex2dec: bad value!\n");
                        exit(1);
        }
}

/* takes a string with \xHH escapes and returns one with the characters
they stand for */
static char * pre_process(char * s)
{
        char * result = malloc(strlen(s) + 1);
        int sindex = 0, rindex = 0;
        while( sindex < strlen(s) )  
        {
            if( sindex + 3 < strlen(s) &&
                s[sindex] == '\\' && s[sindex+1] == 'x' &&
                isxdigit(s[sindex + 2]) && isxdigit(s[sindex + 3]) )
                {
                        /* carefully remember to call tolower here... */
                        result[rindex] = tolower( hex2dec(s[sindex + 2])*16 +
                                                  hex2dec(s[sindex + 3] ) );
                        sindex += 3; /* 4 total */
                }
                else 
                        result[rindex] = tolower(s[sindex]);

                sindex++;  
                rindex++;
        }
        result[rindex] = '\0';

        return result;
}

int main(int argc, char ** argv)
{
	regexp * pattern = (regexp *)malloc(sizeof(struct regexp));
	char * s = argv[1];
	char input[MAX];
	int patternlen, inputlen = 0, c = 0;

	if(!argv[1]){
		fprintf(stderr, "need an arg (the pattern)\n");
		return 1;
	}
	patternlen = strlen(s);
	if(patternlen > MAX_PATTERN_LEN){
		fprintf(stderr, "Pattern is too long!  Max is %d.\n", MAX_PATTERN_LEN);
		return 1;
	}

	s = pre_process(s); /* do \xHH escapes */

	pattern = regcomp(s, &patternlen);

	for(c = 0; c < MAX; c++){
		// assumes there's plenty to eat
		input[inputlen] = getchar();
		inputlen++;
	}
	input[inputlen] = '\0';

	for(c = 0; c < inputlen; c++)	input[c] = tolower(input[c]);

	if(regexec(pattern, input))	puts("Match");
	else				puts("No match");

	return 0;

}
