#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10472);
 script_bugtraq_id(1426);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0575");
 
 name["english"] = "SSH Kerberos issue";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote SSH server does not properly protect the kerberos tickets of
the users.

Description :

The remote host is running a version of SSH which is older than (or as old as) 
version 1.2.27.

There is a flaw in the remote version of this software which allows an attacker
to eavesdrop the kerberos tickets of legitimate users of this service, as sshd 
will set their environment variable KRB5CCNAME to 'none' when they log in. 
As a result, kerberos tickets will be stored in the current working directory 
of the user, as 'none'.

In certain cases, this may allow an attacker to obtain the tickets.


Solution : 

Upgrade to the newest version of SSH.

Risk factor :

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote SSH version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 - 2006 Tenable Network Security");
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


kb = get_kb_item("SSH/supportedauth/" + port );
if ( ! kb || "kerberos" >!< kb ) exit(0);

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

banner = get_backport_banner(banner:banner);


if(ereg(string:banner,
  	pattern:"ssh-.*-1\.([0-1]\..*|2\.([0-1]..*|2[0-7]))[^0-9]*",
	icase:TRUE))security_note(port);
