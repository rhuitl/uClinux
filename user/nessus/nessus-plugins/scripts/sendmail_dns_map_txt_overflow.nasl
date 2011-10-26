#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11232);
 script_bugtraq_id(5122);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2002-0906");
 
 name["english"] = "Sendmail DNS Map TXT record overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to a buffer overflow its DNS handling code.

The owner of a malicious name server could use this flaw
to execute arbitrary code on this host.


Solution : Upgrade to Sendmail 8.12.5
Risk factor : High"; 
	
 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the version number"; 
 summary["francais"] = "Vérification du numéro de version de sendmail";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner && "Switch-" >!< banner )
{
 if(egrep(pattern:".*sendmail +(SMI-.*|8\.([0-9]\.|10\.|11\.[0-6][^0-9]|12\.[0-4][^0-9])|[0-7]\.[0-9]*\.[0-9]*)", string:banner, icase:TRUE))
 	security_hole(port);
}
