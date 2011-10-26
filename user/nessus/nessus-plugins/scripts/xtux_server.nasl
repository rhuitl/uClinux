#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# xtux server will start looping and eat CPU if it receives bad input.
# Writing a nice plugin is useless, as xtux is killed by find_service!
#
# See Bugtraq :
# From:"b0iler _" <b0iler@hotmail.com>
# Subject: xtux server DoS.
# Date: Sat, 09 Mar 2002 15:53:32 -0700

if(description)
{
  script_id(11016);
  script_bugtraq_id(4260);
  script_version ("$Revision: 1.7 $");
  script_cve_id("CVE-2002-0431");
 
  script_name(english:"xtux server detection");
 
  desc["english"] = "
The xtux server might be running on this port. If somebody connects to
it and sends it garbage data, it may loop and overload your CPU.

Solution: disable it, or at least firewall it

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect xtux server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
	family["english"] = "Useless services";
	script_family(english:family["english"]);
	script_require_ports(8390);
	script_dependencie("find_service.nes"); 
	exit(0);
}

include("misc_func.inc");

port = 8390;
kb = known_service(port:port);
if(kb && kb != "xtux")exit(0);

if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if(soc)
	{
		security_warning(port);
		close(soc);
	}
}

