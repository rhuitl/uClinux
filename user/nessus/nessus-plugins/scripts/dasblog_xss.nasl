#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14639);
 script_cve_id("CVE-2004-1657");
 script_bugtraq_id(11086);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "dasBlog HTML Injection Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running dasBlog, a .NET blog system. It is reported that 
versions up to and including 1.6.0 are vulnerable to an HTML injection issue. 
The application does not sanitize the Referer and User-Agent HTTP headers. 
An attacker may use this weakness to include malicious code in the 'Activity 
and Events Viewer' which may be executed by an administrator displaying this 
page.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in dasBlog";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
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
#if(!can_host_asp(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/CategoryView.aspx?category=nessus"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( 'newtelligence' >< r && 
     'dasBlog' >< r &&
      egrep(pattern:"(Powered By:)? newtelligence dasBlog (0\.|1\.([0-5]\.|6\.[0-9][0-9][0-9][0-9]\.0))", string:r) )
 {
 	security_warning(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

