#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#



if(description)
{
 script_id(11592);
 script_bugtraq_id(7355);
 # script_cve_id("CVE-MAP-NOMATCH");
 # NOTE: no CVE id assigned (jfs, december 2003)
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "12Planet Chat Server Path Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running 12Planet Chat Server - a web based chat
server written in Java.

There is a flaw in this version which allows an attacker to obtain
the physical path of the installation by sending a malformed request
to this service.

Knowing this information will help an attacker to make more focused
attacks.

Solution : None at this time
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for 12Planet Chat Server path disclosure";
 
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
  req = http_get(item:"/qwe/qwe/index.html", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(egrep(pattern:"java\.io\.IOException: .* [A-Z]:\\", string:res))
  {
    security_warning(port);
    exit(0);
  }
 }
}
