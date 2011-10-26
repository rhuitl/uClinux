%{

static void
exam (s)
char *s;
{
	char *ptr;

	for (ptr = s; *ptr; ptr++) {

		if (*ptr == '\n' || *ptr == '\t')
			putchar (' ');
		else
			putchar (*ptr);
	}
	putchar ('\n');
}

%}

%START AA

%%

a60_error[ 	\n]+"("[^\,]+\,[^\,]+\,[^\"]+	{ BEGIN AA; }

<AA>\"[^\"]+\"		{ exam (yytext); BEGIN 0; }

.|"\n"			;
<AA>.|"\n"		{ BEGIN 0; }

%%
