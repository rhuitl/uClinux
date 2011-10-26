#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10608);
 script_version ("$Revision: 1.14 $");

 script_bugtraq_id(2356);
 script_xref(name:"OSVDB", value:"504");

 name["english"] = "OpenSSH 2.3.1 authentication bypass vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running OpenSSH 2.3.1.

This version is vulnerable to a flaw which allows any attacker who can
obtain the public key of a valid SSH user to log into this host
without any authentication. 

Solution :
Downgrade to OpenSSH 2.3.0 or upgrade to OpenSSH 2.3.2

Risk factor : High";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("backport.inc"); 

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);
banner = tolower(get_backport_banner(banner:banner));

if("openssh" >< banner)
{
 if("2.3.1" >< banner)security_hole(port);
}
