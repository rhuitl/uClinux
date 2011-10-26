#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14358);
 script_cve_id("CVE-2004-1467");
 script_bugtraq_id(11013);
 script_version("$Revision: 1.7 $");
 
 name["english"] = "eGroupWare Cross-Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running eGroupWare, a web based tool to facilitate
office communication.

The remote version of this software is vulnerable to a cross-site scripting
attack which may allow an attacker to steal the cookies of a legitimate
user by sending him a malformed link to this website.

Solution : Upgrade to the latest version of this software
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in EGroupWare";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("egroupware_detect.nasl");
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

kb  = get_kb_item("www/" + port + "/egroupware");
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb);
loc = stuff[2];

req = http_get(item:string(loc, "/index.php?menuaction=calendar.uicalendar.day&date=20040405<script>foo</script>"), port:port);

r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if( r == NULL )exit(0);
if('<script>foo</script>' >< r ) security_warning(port);
