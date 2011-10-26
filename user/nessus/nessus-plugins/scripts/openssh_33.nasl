#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
#
#
# also covers CVE-2002-0765

if(description)
{
 script_id(11031);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0011");
 script_bugtraq_id(5093);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2002-0639", "CVE-2002-0640");
 
 name["english"] = "OpenSSH <= 3.3";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of OpenSSH which is older than 3.4

There is a flaw in this version that can be exploited remotely to
give an attacker a shell on this host.

Note that several distribution patched this hole without changing
the version number of OpenSSH. Since Nessus solely relied on the
banner of the remote SSH server to perform this check, this might
be a false positive.

If you are running a RedHat host, make sure that the command :
          rpm -q openssh-server
	  
Returns :
	openssh-server-3.1p1-6


Solution : Upgrade to OpenSSH 3.4 or contact your vendor for a patch
Risk factor : High";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 summary["francais"] = "Vérifie la version de SSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 if (  ! defined_func("bn_random") )
 	script_dependencie("ssh_detect.nasl");
 else
 	script_dependencie("ssh_detect.nasl", "redhat-RHSA-2002-131.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("backport.inc"); 

if ( get_kb_item("CVE-2002-0640") ) exit(0);

port = get_kb_item("Services/ssh");
if(!port)port = 22;



banner = get_kb_item("SSH/banner/" + port ) ;
if( ! banner ) exit(0);
banner = get_backport_banner(banner:banner);
banner = tolower(banner);
if("openssh" >< banner)
{
 if(ereg(pattern:".*openssh[-_]((1\..*)|(2\..*)|(3\.([0-3](\.[0-9]*)*)))", string:banner))
	security_hole(port);
}


