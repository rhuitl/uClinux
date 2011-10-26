# (C) Michel Arboi - GPL

if(description)
{
 script_id(17295);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(75);

 name["english"] = "poppassd USER overflow";
 
 script_name(english:name["english"]);
 
desc["english"] = "
The remote poppassd daemon crashes when a too 
long name is sent after the USER command.

It might be possible for a remote cracker to run 
arbitrary code on this machine.

Solution : upgrade your software or use another one

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a too long USER command to poppassd";

 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais: family["francais"]);

 script_require_ports(106, "Services/pop3pw");
 script_dependencies('find_service1.nasl', 'find_service_3digits.nasl');
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/pop3pw");
if (! port) port = 106;

if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

r = recv_line(socket:soc, length:4096);
if (r !~ '^200 ') exit (0);

send(socket: soc, data: 'USER nessus\r\n');
r = recv_line(socket: soc, length: 4096);
if (r !~ '^200 ') exit (0);

send(socket: soc, data: 'PASS '+crap(4096)+'\r\n');
line = recv_line(socket: soc, length: 4096);
close(soc);

sleep(1);

soc = open_sock_tcp(port);
if (! soc) { security_hole(port); exit(0); }

if (report_paranoia > 1 && ! line)
security_hole(port: port, data: "
The remote poppassd daemon abruptly closes the connection
when it receives a too long USER command.

It might be vulnerable to an exploitable buffer overflow; 
so a cracker might run arbitrary code on this machine.

*** Note that Nessus did not crash the service, so this
*** might be a false positive.
*** However, if the poppassd service is run through inetd
*** it is impossible to reliably test this kind of flaw.

Solution : upgrade your software or use another one

Risk factor : High");
