#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(12124);

 script_bugtraq_id(9778);
 script_cve_id("CVE-2004-0189");
 script_xref(name:"OSVDB", value:"5916");

 script_version ("$Revision: 1.7 $");
 name["english"] = "Squid null character unauthorized access";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote squid caching proxy, according to its version number,
is vulnerable to a flaw which may allow an attacker to gain access
to unauthorized resources.

The flaw in itself consists of sending a malformed username containing
the %00 (null) character, which may allow an attacker to access otherwise
restricted resources.

Solution : Upgrade to squid 2.5.STABLE6 or newer
Risk factor : High";

 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines squid version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 
 family["english"] = "Misc."; 
 
 script_family(english:family["english"]);
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
  if(egrep(pattern:"Squid/2\.([0-4]\.|5\.STABLE[0-4][^0-9])", string:res))
      security_hole(port);
}
