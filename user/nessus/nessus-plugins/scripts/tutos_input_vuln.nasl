#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Francois SORIN <francois.sorin@kereval.com>
#
#  This script is released under the GNU GPL v2

if(description)
{
 script_id(14793);
 script_bugtraq_id(10129);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"5326");
 
 script_version("$Revision: 1.3 $");
 name["english"] = "Tutos input validation Issues";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Tutos, an open-source team organization software
package written in PHP.

The remote version of this software is vulnerable to multiple input validation
flaws which may allow an authenticated user to perform a cross site scripting
attack, path disclosure attack or a SQL injection against the remote service.

Solution : Upgrade to Tutos-1.1.20040412 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Tutos";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/php/mytutos.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( '"GENERATOR" content="TUTOS' >< res &&
       egrep(pattern:".*GENERATOR.*TUTOS (0\..*|1\.(0\.|1\.(2003|20040[1-3]|2004040[0-9]|2004041[01])))", string:res) )
	{
	 security_hole(port);
	 exit(0);
	}
 }
