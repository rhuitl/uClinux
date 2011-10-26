#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11343);
 script_bugtraq_id(1949);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2000-1169");
 
 name["english"] = "OpenSSH Client Unauthorized Remote Forwarding";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote SSH client does not disable X11 forwarding.

Description :

The remote host is running a version of the OpenSSH client older than or
as old as version 2.3.0.
 
This version  does not properly disable X11 or agent forwarding, 
which could allow a malicious SSH server to gain access to the X11 
display and sniff X11 events, or gain access to the ssh-agent.

Solution :

Install the newest version of OpenSSH, available at http://www.openssh.com

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi",
		francais:"Ce script est Copyright (C) 2003 Xue Yong Zhi");
 family["english"] = "Gain a shell remotely";
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

	
# Looking for OpenSSH product version number < 2.3
if(ereg(pattern:".*openssh[_-](1|2\.[0-2])\..*",string:banner))security_warning(port);
	
	

