#
# This script was written by Thomas reinke <reinke@e-softinc.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 	script_id(10883);
 	script_bugtraq_id(4241);
	script_version("$Revision: 1.15 $");
	script_cve_id("CVE-2002-0083");
 	name["english"] = "OpenSSH Channel Code Off by 1";
	script_name(english:name["english"]);
 
 	desc["english"] = " 
You are running a version of OpenSSH which is older than 3.1.

Versions prior than 3.1 are vulnerable to an off by one error
that allows local users to gain root access, and it may be
possible for remote users to similarly compromise the daemon
for remote access.

In addition, a vulnerable SSH client may be compromised by
connecting to a malicious SSH daemon that exploits this
vulnerability in the client code, thus compromising the
client system.

Solution : Upgrade to OpenSSH 3.1 or apply the patch for
prior versions. (See: http://www.openssh.org)

Risk factor : High";
	
 	script_description(english:desc["english"]);
 
 	summary["english"] = "Checks for the remote OpenSSH version";
 	script_summary(english:summary["english"]);
 
 	script_category(ACT_GATHER_INFO);
 
 
 	script_copyright(english:
	"This script is Copyright (c) 2002 Thomas Reinke");
  	
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
if(!port) port = 22;


banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);
banner = tolower(get_backport_banner(banner:banner));

if(ereg(pattern:"ssh-.*-openssh[-_](2\..*|3\.0).*" , string:banner))
		security_hole(port);
