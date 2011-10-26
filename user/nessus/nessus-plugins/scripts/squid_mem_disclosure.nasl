#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15929);
 script_cve_id("CVE-2004-2479");
 script_bugtraq_id(11865);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"12282");
 }
 script_version ("$Revision: 1.4 $");
 name["english"] = "Squid Proxy Failed DNS Lookup Random Error Messages";
 script_name(english:name["english"]);
 desc["english"] = "
The remote host running a Squid proxy on this port.

There is a vulnerability in the remote version of this software which may
allow an attacker to disclose the content of its memory by causing the
use of a freed pointer.

Solution:  Apply the vendor released patch, for squid it is located here: 
www.squid-cache.org.  You can also protect yourself by enabling access lists 
on your proxy.
Risk factor : Low";
 script_description(english:desc["english"]);
 summary["english"] = "Checks for the usage of a freed pointer";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencies("find_service.nes", "proxy_use.nasl");
 script_require_ports("Services/http_proxy", 8080, 3128);
 exit(0);
}


include('http_func.inc');
include('http_keepalive.inc');


port = get_kb_item("Services/http_proxy");
if ( ! port ) port = 3128;
res = http_keepalive_send_recv(port:port, data:http_get(item:"http://./nessus.txt", port:port));

if ( "Squid" >< res && egrep(pattern:"http://[^./][^/]*/nessus\.txt", string:res) )
	security_warning(port);
