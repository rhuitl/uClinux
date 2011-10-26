#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10268);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-1085");
 
 name["english"] = "SSH Insertion Attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote SSH server contains a cryptographical weakness which might allow
a third party to decrypt the traffic.

Description :

The remote host is running a version of SSH which is older than (or as old as) 
version 1.2.23.

The remote version of this software is vulnerable to a known plain text attack,
which may allow an attacker to insert encrypted packets in the client - server
stream that will be deciphered by the server, thus allowing the attacker to 
execute arbitrary commands on the remote server

Solution :

Upgrade to version 1.2.25 of SSH which solves this problem.

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
	
	

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 - 2006 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
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

banner = get_backport_banner(banner:banner);

if ( "openssh" >< tolower(banner) ) exit(0);

if(ereg(pattern:"^SSH-.*-1\.2(\.([0-9]|1[0-9]|2[0123])|)$", string:banner))
	security_warning(port);
