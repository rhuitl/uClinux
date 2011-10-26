#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# It is released under the GNU Public Licence 

if(description)
{
 script_id(17141);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(2);
 name["english"] = "fingerd buffer overflow";
 
 script_name(english:name["english"]);
 desc["english"] = "
Nessus was able to crash the remote finger daemon by sending a too long 
request. 

This flaw is probably a buffer overflow and might be exploitable
to run arbitrary code on this machine.

Solution : Disable your finger daemon, apply the latest patches from your 
vendor, or a safer software.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a long command to fingerd";
 
 script_summary(english:summary["english"]);
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");

 family["english"] = "Finger abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "doublecheck_std_services.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
include('global_settings.inc');

port = get_kb_item("Services/finger");
if(!port) port = 79;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

send(socket: soc, data: crap(4096)+ '\r\n');
r = recv(socket:soc, length:65535);

close(soc);

sleep(1);

soc = open_sock_tcp(port);
if(! soc) { security_hole(port); exit(0); }
else close(soc);

if (report_paranoia > 1 && ! r)
security_hole(port: port, data:
"The remote finger daemon abruptly closes the connection
when it receives a too long request.
It might be vulnerable to an exploitable buffer overflow; 
so a cracker might run arbitrary code on this machine.

*** Note that Nessus did not crash the service, so this
*** might be a false positive.
*** However, if the finger service is run through inetd
*** (a very common configuration), it is impossible to 
*** reliably test this kind of flaw.

Solution : Disable your finger daemon,
	 apply the latest patches from your vendor,
	 or a safer software.

Risk factor : High");
