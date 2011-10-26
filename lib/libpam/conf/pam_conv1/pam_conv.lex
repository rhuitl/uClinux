
%{
/*
 * $Id: pam_conv.lex,v 1.2 2005/08/18 11:11:46 kukuk Exp $
 *
 * Copyright (c) Andrew G. Morgan 1997 <morgan@parc.power.net>
 *
 * This file is covered by the Linux-PAM License (which should be
 * distributed with this file.)
 */

    static const char lexid[]=
	"$Id: pam_conv.lex,v 1.2 2005/08/18 11:11:46 kukuk Exp $\n"
	"Copyright (c) Andrew G. Morgan 1997 <morgan@parc.power.net>\n";

    extern int current_line;
%}

%%

"#"[^\n]*         ; /* skip comments (sorry) */

"\\\n" {
    ++current_line;
}

([^\n\t ]|[\\][^\n])+ {
    return TOK;
}

[ \t]+      ; /* Ignore */

<<EOF>> {
    return EOFILE;
}

[\n] {
    ++current_line;
    return NL;
}

%%
