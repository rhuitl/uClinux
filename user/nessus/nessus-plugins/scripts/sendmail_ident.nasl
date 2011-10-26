#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10278);
 script_bugtraq_id(2311);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-1999-0204");
 
 name["english"] = "Sendmail 8.6.9 ident";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to the ident overflow which
allows any remote attacker to execute arbitrary commands as root.

Solution : upgrade to the latest version of Sendmail
Risk factor : High"; 

	
 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the version number"; 
 summary["francais"] = "Vérification du numéro de série de sendmail";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port: port);

# Note that we don't have any smtpscan signature for those servers
if(banner)
{
 if(egrep(pattern:".*Sendmail ((8\.([0-5]\..*|6\.[0-9][^0-9])[^0-9])|SMI-([0-7]|8\.[0-6])).*",
	string:banner))
 	security_hole(port);
}
