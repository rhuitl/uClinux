#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14230);
 script_cve_id("CVE-2004-2624");
 script_bugtraq_id(10860);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8295");
 }
 script_version ("$Revision: 1.9 $");
 name["english"] = "WackoWiki XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running the WackoWiki CGI suite.

Based on the version information gathered by Nessus, this instance 
of WackoWiki may be vulnerable to a remote authentication attack.

Exploitation of this vulnerability may allow for theft of cookie-based 
authentication credentials and cross-site scripting attacks. 

Solution : Update or disable this CGI suite
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for WackoWiki XSS flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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

if(!get_port_state(port))
	exit(0);


function check(url)
{
	req = http_get(item:string(url, "/WackoWiki"),
 		port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);
	#Powered by WackoWiki R4.0
 	if(egrep(pattern:"Powered by .*WackoWiki R3\.5", string:r))
 	{
 		security_warning(port);
		exit(0);
	}
 
}

check(url:"");
foreach dir (cgi_dirs())
{
 check(url:dir);
}



