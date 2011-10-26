#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15972);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2004-1402");
 script_bugtraq_id(11946);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"12417");

 name["english"] = "Multiple SQL Injection Vulnerabilities in iWebNegar";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is subject to
multiple SQL injection vulnerabilities. 

Description :

The remote host appears to be running iWebNegar, a web log application
written in PHP. 

There is a flaw in the remote software that may allow anyone to inject
arbitrary SQL commands and in turn gain administrative access to the
affected application. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2004-12/0175.html

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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
  req = http_get(item:dir + "/index.php?string='", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) exit(0);
  if ("iWebNegar" >< res &&
     egrep(pattern:"mysql_fetch_array\(\).*MySQL", string:res) ) 
	{
	  security_hole(port);
	  exit(0);
	}
 }
