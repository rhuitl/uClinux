#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#

if(description)
{
  script_id(11772);
  script_version("$Revision: 1.5 $");
 
  name["english"] = "Generic SMTP overflows";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote SMTP server crashes when it is send a command 
with a too long argument.

A cracker might use this flaw to kill this service or worse,
execute arbitrary code on your server.
	
Solution : upgrade your MTA or change it.

Risk factor : High";


  script_description(english:desc["english"]);
		    
 
  summary["english"] = "Tries overflows on SMTP commands arguments"; 
  script_summary(english:summary["english"]);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 
  family["english"] = "SMTP problems";
  family["francais"] = "Problèmes SMTP";
  script_family(english:family["english"], francais:family["francais"]);
  script_dependencie("sendmail_expn.nasl", "smtpserver_detect.nasl");
  script_exclude_keys("SMTP/wrapped");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if (! port) port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
banner = smtp_recv_banner(socket:soc);
if (!banner)
{
  close(soc);
  exit(0);
}

cmds = make_list(
	"HELO", 
	"EHLO", 
	"MAIL FROM:", 
	"RCPT TO:", 
	"ETRN");
args = make_list(
	"test.nessus.org", 
	"test.nessus.org", 
	strcat("test@", get_host_name()),
	strcat("test@[", get_host_ip(), "]"),
	"test.nessus.org");
n = max_index(cmds);

for (i = 0; i < n; i ++)
{
  ##display("cmd> ", cmds[i], "\n");
  send(socket: soc, 
       data: string(cmds[i], " ", 
                    str_replace(string: args[i], 
                                find: "test", 
                                replace: crap(4095)),
                    "\r\n"));
  repeat
  {
    data = recv_line(socket: soc, length: 32768);
    ##display("data>  ", data);
  }
  until (data !~ '^[0-9][0-9][0-9]-');
  # A Postfix bug: it answers with two codes on an overflow
  repeat
  {
    data2 = recv_line(socket: soc, length: 32768, timeout: 1);
    ##if (data2) display("data2> ", data2);
  }
  until (data2 !~ '^[0-9][0-9][0-9]-');

  if (! data)
  {
    close(soc);
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_hole(port);
      exit(0);
    }
    for (j = 0; j <= i; j ++)
    {
      send(socket: soc, data: string(cmds[i], " ", args[i], "r\n"));
      data = recv_line(socket: soc, length: 32768);
    }
  }
}

send(socket: soc, data: 'QUIT\r\n');
data = recv_line(socket: soc, length: 32768);
close(soc);
