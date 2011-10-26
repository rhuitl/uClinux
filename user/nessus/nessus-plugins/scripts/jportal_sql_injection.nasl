#
# (C) Tenable Network Security
#


if(description)
{
 script_id(12256);
 script_cve_id("CVE-2004-2036");
 script_bugtraq_id(10430);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"6503");
 }
 script_version("$Revision: 1.5 $");
 name["english"] = "SQL injection in JPortal";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running the JPortal CGI suite.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
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
if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/print.php?what=article&id='", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if (egrep(pattern:"mysql_fetch_array\(\).*MySQL", string:res) ) 
	{
	  security_hole(port);
	  exit(0);
	}
 }
