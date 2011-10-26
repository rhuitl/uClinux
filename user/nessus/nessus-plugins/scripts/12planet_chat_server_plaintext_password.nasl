#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#



if(description)
{
 script_id(11591);
 script_bugtraq_id(7354);
 # script_cve_id("CVE-MAP-NOMATCH");
 # NOTE: no CVE id assigned (jfs, december 2003)

 script_version ("$Revision: 1.5 $");

 name["english"] = "12Planet Chat Server ClearText Password";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running 12Planet Chat Server - a web based chat
server written in Java.

The connection to this server is done over clear text, which means that
an attacker who can sniff the data going to this host could obtain the
administrator password of the web site, and use it to gain unauthorized
access to this chat server.

Solution : None at this time
Risk factor : Low";


 script_description(english:desc["english"]);

 summary["english"] = "Checks for the data encapsulation of 12Planet Chat Server";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);
foreach port (ports)
{
 if(get_port_state(port))
 {
  res = http_get_cache(port:port, item:"/");
  if(res != NULL && "one2planet.tools.PSDynPage" >< res)
  {
    if(get_port_transport(port) == ENCAPS_IP){ security_warning(port); exit(0); }
  }
 }
}
