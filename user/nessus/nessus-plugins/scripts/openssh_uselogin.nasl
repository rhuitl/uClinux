#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10439);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2000-0525");
 script_bugtraq_id(1334);
 script_xref(name:"OSVDB", value:"341");

 name["english"] = "OpenSSH < 2.1.1 UseLogin feature";
 name["francais"] = "OpenSSH < 2.1.1 UseLogin feature";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
You are running a version of OpenSSH which is older than 2.1.1. 

If the UseLogin option is enabled, then sshd does not switch to the
uid of the user logging in.  Instead, sshd relies on login(1) to do
the job.  However, if the user specifies a command for remote
execution, login(1) cannot be used and sshd fails to set the correct
user id, so the command is run with the same privilege as sshd
(usually root privileges). 

*** Note that Nessus did not determine whether the UseLogin
*** option was activated or not, so this message may
*** be a false alarm

Solution : Upgrade to OpenSSH 2.1.1 or make sure
that the option UseLogin is set to no in sshd_config

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the remote OpenSSH version";
 summary["francais"] = "Vérifie la version de OpenSSH";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
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

b = get_backport_banner(banner:banner);

if(ereg(pattern:"SSH-.*-OpenSSH[-_]((1\.*)|(2\.[0-1]))", string:b))
 {
  security_hole(port);
 }
