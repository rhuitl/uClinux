# This NASL script was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence
#
# Date:  Fri, 7 Dec 2001 14:23:10 +0100
# From: "Sebastien EXT-MICHAUD" <Sebastien.EXT-MICHAUD@atofina.com>
# Subject: Lotus Domino Web server vulnerability
# To: bugtraq@securityfocus.com


if (description)
{
  script_id(11718);
  script_bugtraq_id(3656);
  script_cve_id("CVE-2001-0954");
  script_version("$Revision: 1.5 $");
  name["english"] = "Lotus /./ database lock";
  script_name(english:name["english"]);

  desc["english"] = "
It might be possible to lock out some Lotus Domino databases by 
requesting them through the web interface with a special request
like /./name.nsf 
This attack is only efficient on databases that are not used by
the server.

*** Note that no real attack was performed, 
*** so this might be a false alert

Solution: upgrade your Lotus Domino server 
Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Locks out Lotus database with /./ request";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
  family["english"] = "Denial of Service";
  family["francais"] = "Déni de service";
  script_family(english:family["english"], francais:family["french"]);

  script_dependencie("find_service.nes", "http_login.nasl", "httpver.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/domino");
  exit(0);

}

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


b = get_http_banner(port: port);
if(egrep(pattern: "^Server: Lotus-Domino/(Release-)?(5\.0\.[0-8][^0-9])", string:b))
  security_warning(port);
