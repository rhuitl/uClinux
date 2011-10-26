

#
# This script was written by Drew Hintz ( http://guh.nu )
# 
# It is based on scripts written by Renaud Deraison and  HD Moore
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10811);
 script_bugtraq_id(3526);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2001-0815");
 name["english"] = "ActivePerl perlIS.dll Buffer Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
An attacker can run arbitrary code on the remote computer.
This is because the remote IIS server is running a version of
ActivePerl prior to 5.6.1.630 and has the Check that file
exists option disabled for the perlIS.dll.  

Solution:  Either upgrade to a version of ActivePerl more
recent than 5.6.1.629 or enable the Check that file exists option.
To enable this option, open up the IIS MMC, right click on a (virtual)
directory in your web server, choose Properties, 
click on the Configuration... button, highlight the .plx item,
click Edit, and then check Check that file exists.

More Information: http://www.securityfocus.com/bid/3526

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if arbitrary commands can be executed thanks to ActivePerl's perlIS.dll";
 
 script_summary(english:summary["english"]);
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);


function check(req)
{
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(r == NULL)exit(0);

 if ("HTTP/1.1 500 Server Error" >< r &&
     ("The remote procedure call failed." >< r ||
      "<html><head><title>Error</title>" >< r))
 {
   security_hole(port:port);
   return(1);
 }
 return(0);
}

dir[0] = "/scripts/";
dir[1] = "/cgi-bin/";
dir[2] = "/";

for(d = 0; dir[d]; d = d + 1)
{
	url = string(dir[d], crap(660), ".plx"); #by default perlIS.dll handles .plx
	if(check(req:url))exit(0);

	url = string(dir[d], crap(660), ".pl");
	if(check(req:url))exit(0);
}
