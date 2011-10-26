#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10607);
 script_bugtraq_id(2347);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2001-0144");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-A-0013");
 
 
 name["english"] = "SSH1 CRC-32 compensation attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to execute arbitrary code on the remote host.

Description :

The remote host is running a version of SSH which is older than version 1.2.32,
or a version of OpenSSH which is older than 2.3.0.

The remote version of this software is vulnerable to a flaw known as a 'CRC-32
compensation attack' which may allow an attacker to gain a root shell on this 
host.

Solution :

Upgrade to version 1.2.32 of SSH which solves this problem,
or to version 2.3.0 of OpenSSH

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 - 2006 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
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
 if(ereg(pattern:"ssh-.*-openssh(-|_)((1\..*)|2\.[0-2]([^0-9]|$))",
	 string:banner))security_hole(port);
}
else
{
if(ereg(pattern:"ssh-.*-1\.2\.(2[4-9]|3[01])([^0-9]|$)", string:banner))
	security_hole(port);
}
