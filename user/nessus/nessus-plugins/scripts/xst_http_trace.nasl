#
# This script was written by Thomas Reinke <reinke@securityspace.com>
# Improvements re TRACK and RFP reference courtesy of <sullo@cirt.net>
# Improvements by rd - http_get() to get full HTTP/1.1 support, 
# security_warning() instead of security_hole(), slight re-phrasing
# of the description
#
# See the Nessus Scripts License for details
#
# Fixes by Tenable:
#   - added CVE xref.

 desc["english"] = '
Synopsis :

Debugging functions are enabled on the remote HTTP server.

Description :

The remote webserver supports the TRACE and/or TRACK methods. TRACE and TRACK
are HTTP methods which are used to debug web server connections.   

It has been shown that servers supporting this method are subject to
cross-site-scripting attacks, dubbed XST for "Cross-Site-Tracing", when
used in conjunction with various weaknesses in browsers. 

An attacker may use this flaw to trick your legitimate web users to give
him their credentials. 

Solution :

Disable these methods.

See also :

http://www.kb.cert.org/vuls/id/867593

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)';


if(description)
{
 script_id(11213);
 script_version ("$Revision: 1.26 $");
 name["english"] = "HTTP TRACE Method Enabled";
 script_name(english:name["english"]);
 script_cve_id("CVE-2004-2320");
 script_bugtraq_id(9506, 9561, 11604);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "http TRACE XSS attack";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 E-Soft Inc.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}



sol["apache"] = "
Solution : 
Add the following lines for each virtual host in your configuration file :

    RewriteEngine on
    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
    RewriteRule .* - [F]

";

sol["iis"] = "
Solution : Use the URLScan tool to deny HTTP TRACE requests or to permit only the methods 
needed to meet site requirements and policy.";

sol["SunONE"] = '
Solution : Add the following to the default object section in obj.conf:
    <Client method="TRACE">
     AuthTrans fn="set-variable"
     remove-headers="transfer-encoding"
     set-headers="content-length: -1"
     error="501"
    </Client>

If you are using Sun ONE Web Server releases 6.0 SP2 or below, compile
the NSAPI plugin located at:
   http://sunsolve.sun.com/pub-cgi/retrieve.pl?doc=fsalert%2F50603';



#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);


if ( egrep(pattern:"^Server:.*IIS", string:banner) ) report = sol["iis"];
else if ( egrep(pattern:"^Server:.*Apache", string:banner) ) report = sol["apache"];
else if ( egrep(pattern:"^Server.*SunONE", string:banner) ) report = sol["SunONE"];

report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);

file = "/Nessus"+rand() + ".html";	# Does not exist

    cmd1 = http_get(item: file, port:port);
    cmd2 = cmd1;
    
    cmd1 = ereg_replace(pattern:"GET /", string:cmd1, replace:"TRACE /");
    cmd2 = ereg_replace(pattern:"GET /", string:cmd2, replace:"TRACK /");

    ua = egrep(pattern:"^User-Agent", string:cmd1);
 
    reply = http_keepalive_send_recv(port:port, data:cmd1, bodyonly:TRUE);
    if ( reply == NULL ) exit(0);
    if(egrep(pattern:"^TRACE "+file+" HTTP/1\.", string:reply))
    {
	if ( ua && ua >!< reply ) exit(0);
	security_note(port:port, data:report);
	exit(0);
    }
   

    reply = http_keepalive_send_recv(port:port, data:cmd2, bodyonly:TRUE);
    if(egrep(pattern:"^TRACK "+file+" HTTP/1\.", string:reply))
    {
       if ( ua && ua >!< reply ) exit(0);

       security_note(port:port, data:report);
    }

