#
# (C) Tenable Network Security
#


if (description)
{
 script_id(12045);
 script_cve_id("CVE-2004-2072");
 script_bugtraq_id(9588);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"3833");
 script_version ("$Revision: 1.7 $");

 script_name(english:"Mambo Site Server itemid Parameter XSS");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a cross-
site scripting attack. 

Description :

An attacker may use the installed version of Mambo Site Server to
perform a cross site scripting attack on the remote host. 

Solution: 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if Mambo Site Server is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 url = string(dir, "/index.php?option=content&task=view&id=1&Itemid=<script>foo</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
 if ( "<script>foo</script>" >< buf)
    security_note(port);
}
