#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      Should also cover BugtraqID: 4560, BugtraqID: 4241/(CVE-2002-0083)
# 
# If the plugin is successful, it will issue a security_hole(). Should
# it attempt to determine if the remote host is a kerberos client and
# issue a security_warning() if it's not ?
#

if(description)
{
 script_id(10802);
 script_bugtraq_id(3560, 4241, 4560);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2002-0083");
 
 name["english"] = "OpenSSH < 3.0.1";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of OpenSSH which is older than 3.0.1.

Versions older than 3.0.1 are vulnerable to a flaw in which
an attacker may authenticate, provided that Kerberos V support
has been enabled (which is not the case by default). 
It is also vulnerable as an excessive memory clearing bug, 
believed to be unexploitable.

*** You may ignore this warning if this host is not using
*** Kerberos V

Solution : Upgrade to OpenSSH 3.0.1

Risk factor : Low (if you are not using Kerberos) / High (if kerberos is enabled)";
	
	

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

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = tolower(get_backport_banner(banner:banner));

if("openssh" >< banner)
{
 if(ereg(pattern:".*openssh[-_]((1\..*)|(2\..*)|(3\.0[^\.]))[^0-9]*", string:banner))
	security_hole(port);
}
