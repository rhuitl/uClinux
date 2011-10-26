#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14185);
 script_cve_id("CVE-2004-2242");
 script_bugtraq_id(10822);
 script_version ("$Revision: 1.6 $"); 
 name["english"] = "Phorum Search Cross Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that suffers from a cross-
site scripting flaw. 

Description :

The remote version of Phorum contains a script called 'search.php'
that is vulnerable to a cross-site scripting attack.  An attacker may
be able to exploit this problem to steal the authentication
credentials of third-party users. 

See also :

http://securitytracker.com/alerts/2004/Jul/1010787.html
http://www.phorum.org/cvs-changelog-5.txt

Solution : 

Upgrade to 5.0.7a.beta or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in Phorum";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencies("phorum_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
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
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 req = http_get(item:string(loc, "/search.php?12,search=vamp,page=1,match_type=ALL,match_dates=00,match_forum=ALL ,body=,author=,subject=<script>foo</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL ) exit(0);
 if("<script>foo</script>" >< r)
   security_note(port);
}
