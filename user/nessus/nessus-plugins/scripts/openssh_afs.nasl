#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10954);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0011");
 script_bugtraq_id(4560);
 script_cve_id("CVE-2002-0575");
 script_version ("$Revision: 1.16 $");
 
 name["english"] = "OpenSSH AFS/Kerberos ticket/token passing";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of OpenSSH older than OpenSSH 3.2.1

A buffer overflow exists in the daemon if AFS is enabled on
your system, or if the options KerberosTgtPassing or
AFSTokenPassing are enabled.  Even in this scenario, the
vulnerability may be avoided by enabling UsePrivilegeSeparation.

Versions prior to 2.9.9 are vulnerable to a remote root
exploit. Versions prior to 3.2.1 are vulnerable to a local
root exploit.

Solution :
Upgrade to the latest version of OpenSSH

Risk factor : High";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Thomas Reinke");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
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


banner = get_kb_item("SSH/banner/" + port );
if(!banner)exit(0);


banner = tolower(get_backport_banner(banner:banner));

if(ereg(pattern:".*openssh[-_](2\..*|3\.([01].*|2\.0)).*", 
	string:banner)) security_hole(port);
