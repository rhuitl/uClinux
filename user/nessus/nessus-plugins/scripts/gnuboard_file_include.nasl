#
# This script is (C) Tenable Network Security
#



if(description)
{
 script_id(15975);
 script_cve_id("CVE-2004-1403");
 script_bugtraq_id(11948);
 script_version ("$Revision: 1.4 $");

 name["english"] = "SIR GNUBoard Remote File Inclusion";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote web server read arbitrary files by 
using the GNUBoard CGI suite which is installed.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to the latest version
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of index.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/index.php?doc=http://xxxxxx./foo.php"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if( "http://xxxxxx./" >< res &&
     "php_network_getaddresses" >< res )
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
