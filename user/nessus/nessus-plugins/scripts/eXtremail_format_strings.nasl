#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: http://online.securityfocus.com/archive/1/192791
#
# Could not find a vulnerable copy -> we rely on banner version instead
#
# *untested*

if(description)
{
 script_id(11100);
 script_bugtraq_id(2908);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2001-1078");
 
 name["english"] = "eXtremail format strings";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote eXtremail server, according to its version number,
may be vulnerable to a format string attack.

An attacker may use this flaw to gain a shell on this host.


Solution : Upgrade to eXtremail 1.1.10 or newer
Risk factor : High"; 
	
 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks the version number"; 
 summary["francais"] = "Vérification du numéro de série de eXtremail";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
 if(egrep(pattern:".*eXtremail V1\.1\.[5-9][^0-9]*", string:banner))
 	security_hole(port);
}

