#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12059);
 script_cve_id("CVE-2004-2087");
 script_bugtraq_id(9647);
 if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"3922");
 }
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "SandSurfer User Authentication Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SandSurfer, a web-based time keeping application.

A vulnerability has been disclosed in all versions of this software, up to
version 1.6.5 (included) which may allow an attacker to access the application
without authenticating.

Solution : Upgrade to SandSurfer 1.7.0.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SandSurfer";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security"); 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d ( cgi_dirs() )
{
 # SandSurfer installs under $prefix/cgi-bin/login.cgi
 req = http_get(item:string(d, "/cgi-bin/login.cgi"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if( egrep(pattern:"SandSurfer (0\.|1\.[0-5]\.)", string:res)){
 	security_warning(port);
	exit(0);
 }
 req = http_get(item:string(d, "/login.cgi"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if( egrep(pattern:"SandSurfer (0\.|1\.[0-5]\.)", string:res)){
 	security_warning(port);
	exit(0);
 }
}
