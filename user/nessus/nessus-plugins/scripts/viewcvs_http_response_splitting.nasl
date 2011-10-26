#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16062);
 script_bugtraq_id(12112, 11819);
 script_cve_id("CVE-2004-1062");
 script_version("$Revision: 1.5 $");

 name["english"] = "ViewCVS HTTP Response Splitting";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running ViewCVS, a tool to browse CVS repositories over
the web written in python.

There is a flaw in the remote version of this web site which may allow 
an attacker to use the remote site thru an HTTP response splitting attack
to steal the credentials of third-party users.

Solution : Upgrade to ViewCVS 1.0.0 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "viewcvs flaw";
 
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
if( ! can_host_php(port:port) ) exit(0);
foreach dir (make_list( cgi_dirs() ) ) 
{
 req = http_get(item:dir + "/viewcvs.cgi/", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( 'Powered by<br><a href="http://viewcvs.sourceforge.net/">ViewCVS 0.' >< res )
 {
	 security_warning(port);
	 exit(0);
 }
}
