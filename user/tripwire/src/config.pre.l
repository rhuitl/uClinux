%{
/* $Id: config.pre.l,v 1.13 1994/07/25 15:40:55 gkim Exp $ */

/*
 * config.pre.l
 *
 *	lexical analyzer for preprocessing tw.config files.
 *
 *	note that escaped sequences in the <string> token must be 
 *	expanded manually.
 *
 * Gene Kim
 * Purdue University
 * October 4, 1992
 */

			/* 
			 * note that strings can contain '@'s, but they
			 * cannot start with them! 
			 *
			 * similarly, we can have #'s in strings, but they
			 * cannot be the first character! 
			 */

%}

WS			[ \t]
COMMENT			[#]
EOL			[\n]
DIRECTIVE		@{2,2}
STRING			([^ \t\n\#\(\)]|\\.)+([^ \t\n\(\)]|\\.)*
LPAREN			[\(]
RPAREN			[\)]
ANDAND			\&{2,2}
OROR			\|{2,2}
BSLASH			[\\]

%%

{WS}+			{ /* eat spaces */ }
{BSLASH}{EOL}		{   
			    /* eat line continuations */ 
			    linenumber++; 
			}
{COMMENT}[^\n]*		{ /* eat comments */ }

^{DIRECTIVE}{WS}*include	{ return INCLUDE; }
^{DIRECTIVE}{WS}*define		{ return DEFINE; }
^{DIRECTIVE}{WS}*undef		{ return UNDEF; }
^{DIRECTIVE}{WS}*ifdef		{ return IFDEF; }
^{DIRECTIVE}{WS}*ifndef		{ return IFNDEF; }
^{DIRECTIVE}{WS}*ifhost		{ return IFHOST; }
^{DIRECTIVE}{WS}*ifnhost	{ return IFNHOST; }
^{DIRECTIVE}{WS}*contents	{ return CONTENTS; }
^{DIRECTIVE}{WS}*dbaseversion	{ return DBASEVERSION; }
^{DIRECTIVE}{WS}*else		{ return ELSE; }
^{DIRECTIVE}{WS}*endif		{ return ENDIF; }
^{DIRECTIVE}{WS}*echo		{ return ECHOTHIS; }
{EOL}			{ linenumber++; return EOL; }
{ANDAND}		{ return ANDAND; }
{OROR}			{ return OROR; }
{LPAREN}		{ return LPAREN; }
{RPAREN}		{ return RPAREN; }
{STRING}		{
    char *pcin, *pcout, macro[1024], *pcm;
    static char outstring[1024];
    char *pctmp;

    yytext[yyleng] = '\0';
    yylval.string = yytext;

    SPDEBUG(20) { printf("---(prestring)---> %s\n", yytext); }

    pcin = yytext;
    pcout = outstring;
    for (; *pcin; pcin++) {
	/* check for macro expansion */
	if (*pcin == '@' && *(pcin+1) && *(pcin+1) == '@') {
	    int curlymode = 0;		/* bounded by '{' and '}' */
	    pcm = macro;
	    pcin += 2;
	    while (*pcin && (isalnum(*pcin) || *pcin == '_' ||
					*pcin == '{' || *pcin == '}')) {
		if (*pcin == '{') {
		    /* nested curlies are not allowed! */
		    if (curlymode) {
			fprintf(stderr, "warning: line %d: nested `{}' expressions are not allowed!\n", linenumber);
		    } else {
			curlymode = 1;
		    }
		    pcin++;
		    continue;
		}
		if (curlymode && *pcin == '}') {
		    pcin++;
		    curlymode = 0;
		    break;
		}

		*pcm++ = *pcin++;
	    }
	    *pcm++ = '\0';

	    SPDEBUG(20) { printf("--(macro)--> %s\n", macro); }

	    /* expand macro */
	    if (tw_mac_ifdef(macro) == 0) {
		fprintf(stderr, "warning: uninitialized directive '%s' at line %d in config file\n\t'%s' !\n\t\t(Hint: maybe a misspelled directive?)\n", macro, linenumber,
					currparsefile);
	    } else {
		/* else substitute in the input stream */
		pctmp = tw_mac_dereference(macro);
		assert(pctmp != NULL);
		SPDEBUG(20) { printf("--(dmacro)--> %s\n", pctmp); }

		strcpy(pcout, pctmp);
		pcout += strlen(pctmp);
	    }
	    pcin--;			/* rewind for loop */
	    continue;
	}
	*pcout++ = *pcin;
    }
    *pcout++ = '\0';


    yylval.string = outstring;
    if (yaccdebuglevel > 10) 
	printf("--(STRING)--> %s\n", outstring);
    return STRING;

}

