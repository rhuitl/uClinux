#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref: http://www.ssh.com/company/newsroom/article/286/
#
# Note: This is about SSH.com's SSH, not OpenSSH !!
#

if(description)
{
 script_id(11169);
 script_bugtraq_id(6247);
 script_cve_id("CVE-2002-1644");
 script_version ("$Revision: 1.8 $");
 
 
 name["english"] = "SSH setsid() vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
You are running a version of SSH which is older than version 3.1.5 or 3.2.2.

There is a bug in that version which may allow a user to obtain higher 
privileges due to a flaw in the way setsid() is used.


Solution : Upgrade to the latest version of SSH
See also : http://www.ssh.com/company/newsroom/article/286/
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

if("f-secure" >< banner)exit(0);

if(ereg(pattern:"^ssh-.*-2\.0\.1[0-3][^0-9].*$", string:banner))
	security_hole(port);
	
if(ereg(pattern:"^ssh-.*-3\.1\.[0-4][^0-9].*$", string:banner))
	security_hole(port);
	
if(ereg(pattern:"^ssh-.*-3\.2\.[0-1][^0-9].*$", string:banner))
	security_hole(port);	

