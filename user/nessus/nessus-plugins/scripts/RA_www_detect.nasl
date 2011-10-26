#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Broken link deleted
#
# GPL
#

if(description)
{
  script_id(10920);
  script_version ("$Revision: 1.9 $");
 
  script_name(english:"RemotelyAnywhere WWW detection");
 
  desc["english"] = "
The RemotelyAnywhere WWW server is running on this system.
According to NAVCIRT attackers love this management tool.

If you installed it, ignore this warning. If not, your machine is 
compromised by an attacker.

Risk factor : None / High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect RemotelyAnywhere www server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
  family["english"] = "Backdoors";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 2000, 2001);
  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2000);
ports = add_port_in_list(list:ports, port:2001);


foreach port (ports)
{
 banner = get_http_banner(port:port);

 if (! banner) exit(0);

 if (egrep(pattern:"^Server: *RemotelyAnywhere", string:banner))
 {
  security_note(port);
 }
}
# TBD: check default account administrator / remotelyanywhere
