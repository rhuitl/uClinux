#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15968);
 script_cve_id("CVE-2004-1401");
 script_bugtraq_id(11933);
 script_version("$Revision: 1.5 $");
 name["english"] = "ASP-Rider SQL Injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running ASP-Rider, a set of ASP scripts
designed to maintain a blog.

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
if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  res = http_keepalive_send_recv(data:http_get(item:dir + "/verify.asp?username='", port:port), port:port);
  if ( res == NULL ) exit(0);
  if ("80040e14" >< res &&
      "'username=''''" ><  res )
	security_hole(port);
 }
