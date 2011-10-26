#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15974);
 script_cve_id("CVE-2004-1400");
 script_bugtraq_id(11931);
 script_version("$Revision: 1.4 $");
 name["english"] = "Ocean12 ASP Calendar Administrative Access";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Ocean12 ASP Calendar, a web based
application written in ASP.

There is a flaw in the remote software which may allow anyone
execute admnistrative commands on the remote host by requesting
the page /admin/main.asp.

An attacker may exploit this flaw to deface the remote site without
any credentials.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "auth bypass test";
 
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

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/admin/main.asp", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ("<title>Ocean12 ASP Calendar Manager</title>" >< res &&
      '<a href="add.asp">' >< res )
	{
	  security_hole(port);
	  exit(0);
	}
 }
