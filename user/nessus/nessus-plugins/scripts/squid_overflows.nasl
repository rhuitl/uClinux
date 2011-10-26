#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10923);

 script_bugtraq_id(4148);
 script_cve_id("CVE-2002-0068");
 script_xref(name:"OSVDB", value:"5378");

 script_version ("$Revision: 1.12 $");
 name["english"] = "Squid overflows";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote squid caching proxy, according to its version number,
is vulnerable to various buffer overflows. 


An attacker may use these to gain a shell on this system.


Solution : upgrade to squid 2.4.STABLE7 or newer
Risk factor : High";

 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines squid version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 
 family["english"] = "Gain a shell remotely"; 
 family["francais"] = "Obtenir un shell à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/http_proxy",3128, 8080);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/http_proxy");
if(!port)
{
 if(get_port_state(3128))
 { 
  port = 3128;
 }
 else port = 8080;
}

if(get_port_state(port))
{
  res = http_get_cache(item:"/", port:port);
  if(egrep(pattern:"Squid/2\.([0-3]\.|4\.STABLE[0-6]([^0-9]|$))", string:res))
      security_hole(port);
}
