#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16190);
 script_cve_id("CVE-2005-0173", "CVE-2005-0211");
 script_bugtraq_id(12275, 12276, 12412, 12433, 12432, 12431, 13434, 13435);
 script_version ("$Revision: 1.6 $");
 name["english"] = "Squid Multiple Flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote squid caching proxy, according to its version number,
is vulnerable to various security flaws :

- There is a buffer overflow issue when handling the reply of 
a rogue gopher site. To exploit this issue, an attacker would
need to use the remote proxy to visit a specially setup gopher
site generating malformed replies ;

- There is a denial of service vulnerability in the WCCP code 
of the remote proxy. To exploit this flaw, an attacker would need
to guess the IP of the WCCP router used by the proxy and spoof a
malformed UDP packet using the router IP address.

- There is a buffer overflow in the WCCP code which may allow an attacker
to execute arbitrary code on the remote host

- There is a flaw in the 'squid_ldap_auth' module which may allow
an attacker to bypass authentication and to gain access to the
remote proxy 

- There is a flaw in the way Squid parses HTTP reply headers


*** Given the way the Squid team handles releases, this may be a
*** false positive. Make sure that all the appropriate patches
*** have been applied.

Solution : Upgrade to squid 2.5.STABLE8 (when available) or newer
See also : http://www.squid-cache.org/Versions/v2/2.5/bugs/
Risk factor : High";

 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines squid version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 family["english"] = "Misc."; 
 
 script_family(english:family["english"]);
 script_dependencie("proxy_use.nasl");
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
  if(res && egrep(pattern:"[Ss]quid/2\.([0-4]\.|5\.STABLE[0-7][^0-9])", string:res))
      security_warning(port);
}
