#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14784);
 script_cve_id("CVE-2004-2161", "CVE-2004-2162");
 script_bugtraq_id(8011, 8012, 11221);
 script_version("$Revision: 1.7 $");
 name["english"] = "Tutos SQL injection and Cross Site Scripting Issues";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Tutos, an open-source team organization software
package written in PHP.

The remote version of this software is vulnerable to multiple input validation
flaws which may allow an authenticated user to perform a cross site scripting
attack or a SQL injection against the remote service.

Solution : Upgrade to Tutos-1.2 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of Tutos";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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


foreach dir (make_list( cgi_dirs() )) 
 {
  req = http_get(item:dir + "/php/mytutos.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( '"GENERATOR" content="TUTOS' >< res &&
       egrep(pattern:".*GENERATOR.*TUTOS (0\..*|1\.[01]\.)", string:res) )
	{
	 security_hole(port);
	 exit(0);
	}
 }
