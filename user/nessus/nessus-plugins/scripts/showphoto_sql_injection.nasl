#
# (C) Tenable Network Security
#


if(description)
{
 script_id(12038);
 script_cve_id("CVE-2004-0239", "CVE-2004-0250");
 script_bugtraq_id(9557);
 script_version("$Revision: 1.9 $");
 name["english"] = "SQL injections in Photopost PHP Pro"; 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running Photopost PHP Pro, a 
web-based photo gallery management system.

There are multiple flaws in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host.

Solution : Upgrade to the latest version of this software.
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


function check(dir)
{
 req = http_get(item:dir + "/showphoto.php?photo=123'", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 
 if ("id,user,userid,cat,date,title,description,keywords,bigimage,width,height,filesize,views,medwidth,medheight,medsize,approved,rating" >< res ) {
	security_hole(port);
	exit(0);
	}
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (cgi_dirs()) 
 {
  check(dir:dir);
 }
