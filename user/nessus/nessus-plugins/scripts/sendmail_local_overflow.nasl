#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# References
# [also vulnerable to a heap overflow]
# Date:  Mon, 28 May 2001 18:16:57 -0400 (EDT)
# From: "Michal Zalewski" <lcamtuf@bos.bindview.com>
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: Unsafe Signal Handling in Sendmail
#

if(description)
{
 script_id(10729);
 script_bugtraq_id(3163);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-0653");
 
 name["english"] = "Sendmail 8.11 local overflow";
 name["francais"] = "Dépassement de buffer local dans sendmail 8.11";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote sendmail server, according to its version number,
may be vulnerable to a local buffer overflow allowing local
users to gain root privileges.

Solution : Upgrade to Sendmail 8.12beta19 or 8.11.6
Risk factor : High (Local) / None (remote with no account)"; 
	
 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the version number"; 
 summary["francais"] = "Vérification du numéro de série de sendmail";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 
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
 if(egrep(pattern:".*sendmail.*8\.((11\.[0-5])|12.*beta([0-9][^0-9]|1[0-8]))/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
