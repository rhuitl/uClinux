#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
#
# This script replaces bind_bof.nes
#

if(description)
{
 script_id(10329);
 script_bugtraq_id(134);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-1999-0009");
 
 
 name["english"] = "BIND iquery overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote BIND server, according to its
version number, is vulnerable to an inverse
query overflow.

Solution : upgrade to bind 8.1.2 or 4.9.7
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote BIND version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.((0\.*)|(1\.[0-1])).*"))security_hole(53);

if(ereg(string:vers,
    	pattern:"^4\.([0-8]|9\.[0-6]).*"))security_hole(53);

