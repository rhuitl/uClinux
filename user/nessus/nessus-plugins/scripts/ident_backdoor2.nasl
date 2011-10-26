# Written by Michel Arboi <mikhail@nessus.org>
# GPL
# 
# I'm not sure what this backdoor is...
#

if(description)
{
 script_id(18392);
 script_version ("$Revision: 1.1 $");
 desc = "
This host seems to be running an ident server, but before any 
request is sent, the server gives an answer about a connection 
to port 6667.

It is very likely this system has heen compromised by an IRC 
bot and is now a 'zombi' that can participate into 'distributed 
denial of service' (DDoS).

Solution: desinfect or re-install your system
Risk factor: High";

 script_name(english: "IRC bot detection");
 script_description(english:desc);
 script_summary(english: "Fake IDENT server (IRC bot)");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Backdoors");
 script_require_ports("Services/fake-identd", 113);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#

# include('misc_func.inc');

regex = '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+';

port = get_kb_item('Services/fake-identd');
if (! port) port = 113;

if (! get_port_state(port)) exit(0);

b = get_kb_item('FindService/tcp/'+port+'/spontaneous');
# if (! b) b = get_unknown_banner(port: port);
if (! b) exit(0);

if (b =~ '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+')
  security_hole(port);
