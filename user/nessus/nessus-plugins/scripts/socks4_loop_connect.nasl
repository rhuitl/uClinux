#
# This script was written by Michel Arboi <mikhail@nessus.org
# GPL
# 
# Socks4 protocol is described on 
# http://www.socks.nec.com/protocol/socks4.protocol
# Socks4a extension is described on 
# http://www.socks.nec.com/protocol/socks4a.protocol
#


if(description)
{
 script_id(17155);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Connect back to SOCKS4 server";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to connect to the SOCKS4 server
through itself. 
This allow anybody to saturate the proxy CPU, memory or 
file descriptors.

Solution: reconfigure your proxy so that it refuses connections to itself
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Connect back to SOCKS4 proxy";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/socks4", 1080);
 script_dependencie("find_service.nes", "find_service2.nasl");
 exit(0);
}

#

# include("dump.inc");

port = get_kb_item("Services/socks4");
if (! port) port = 1080;
if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);

p2 = port % 256;
p1 = port / 256;
a = split(get_host_ip(), sep: '.');


cmd = raw_string(4, 1, p1, p2, int(a[0]), int(a[1]), int(a[2]), int(a[3]))
	+ "root" + '\0';
for (i = 3; i >= 0; i --)
{
  send(socket: s, data: cmd);
  data = recv(socket: s, length: 8, min: 8);
  # dump(ddata: data, dtitle: "socks");
  if (strlen(data) != 8 || ord(data[0]) != 4 || ord(data[1]) != 90) break;
}

close(s);
if (i < 0) security_hole(port);
