#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14640);
 script_bugtraq_id(11085);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Cerbere HTTP Proxy Denial of Service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Cerbere Proxy Server, a HTTP/FTP proxy server for 
Windows operating systems. It is reported that versions up to and including 
1.2 are vulnerable to a remote denial of service in the 'Host:' HTTP field 
processing. An attacker may craft a malicious HTTP request with a large 
'Host:' field to deny service to legetimate users.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of the remote Cerbere Proxy";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 3128);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:3128);
if(!get_port_state(port))exit(0);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if ( egrep(pattern:"Cerb&egrave;re Proxy Server r.(0\.|1.[0-2][^0-9])", string:res) ) security_warning(port); 


