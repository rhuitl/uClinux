#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
#ref: Georgi Guninski (June 2004)
#
# This script is released under the GNU GPLv2



if(description)
{
 script_id(12293);
 script_bugtraq_id(10619, 12877);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2004-0493");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7269");
  
 name["english"] = "Apache Input Header Folding and mod_ssl ssl_io_filter_cleanup DoS Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server is prone to multiple denial of service attacks. 

Description :

The remote host appears to be running a version of Apache 2.x which is
older than 2.0.50. 

There is denial of service flaw in Apache 2.0.x that can be triggered
by sending a specially-crafted HTTP request, which results in the
consumption of an arbitrary amount of memory.  On 64-bit systems with
more than 4GB virtual memory, this may lead to heap based buffer
overflow. 

There is also a denial of service vulnerability in mod_ssl's
'ssl_io_filter_cleanup' function.  By sending a request to vulnerable
server over SSL and closing the connection before the server can send
a response, an attacker can cause a memory violation that crashes the
server. 

See also :

http://www.guninski.com/httpd1.html

Solution : 

Upgrade to Apache 2.0.50 or newer.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
if(egrep(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(([0-9][^0-9])([0-3][0-9][^0-9])|(4[0-9][^0-9])).*", string:banner))
 {
   security_note(port);
 }
}
