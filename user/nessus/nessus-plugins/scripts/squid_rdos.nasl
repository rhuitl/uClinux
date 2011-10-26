#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: iDEFENSE 10.11.04
#
# This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15463);

 script_bugtraq_id(11385);
 script_cve_id("CVE-2004-0918");
 script_xref(name:"OSVDB", value:"10675");

 script_version ("$Revision: 1.8 $");
 name["english"] = "Squid remote denial of service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote squid caching proxy, according to its version number, may be 
vulnerable to a remote denial of service.

This flaw is caused due to an input validation error in the SNMP module.

An attacker can exploit this flaw to crash the server with a specially
crafted UDP packet.

*** Nessus reports this vulnerability using only
*** information that was gathered, so this might 
*** be a false positive.

Solution : Upgrade to squid 2.5.STABLE7 or newer
Risk factor : High";

 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines squid version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Denial of Service";
 
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 if ( defined_func("bn_random") ) 
	script_dependencie("redhat-RHSA-2004-591.nasl");
 script_require_ports("Services/http_proxy",3128, 8080);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

if ( get_kb_item("CVE-2004-0918") ) exit(0);

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
  if(egrep(pattern:"Squid/2\.([0-4]\.|5\.STABLE[0-6]([^0-9]|$))", string:res))
      security_hole(port);
}
