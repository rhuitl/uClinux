#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14187);
 script_cve_id("CVE-2004-2062", "CVE-2004-2063");
 script_bugtraq_id(10821);
 script_version("$Revision: 1.6 $");
 name["english"] = "SQL injection in Antiboard";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running the AntiBoard bulletin board
system.

There are multiple SQL injections vulnerabilities in the remote software
which may allow an attacker to execute arbitary SQL commands on the remote
host, and possibly to bypass the authentication mechanisms of AntiBoard.

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
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:"/antiboard.php?thread_id='", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ("SELECT * FROM antiboard_threads WHERE thread_id =" >< res )
  {	
	 security_hole(port);
 	 exit(0);
  }
 }
