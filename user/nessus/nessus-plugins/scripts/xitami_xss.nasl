#
# (C) Tenable Network Security
#

if(description)
{
 script_id(13841);
 script_bugtraq_id(10778);
 script_version ("$Revision: 1.5 $");

 
 name["english"] = "Xitami Cross Site Scripting Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a script that is affected by a cross-
site scripting flaw. 

Description :

The remote Xitami server is distributed with a script for testing
server-side includes, '/testssi.ssi'.  This script is vulnerable to a
cross-site scripting issue when sent a request with a malformed Host
or User-Agent header.  An attacker may exploit this flaw the steal the
authentication credentials of third-party users. 

See also :

http://www.oliverkarow.de/research/xitami25c1_testssi_XSS.txt

Solution : 

Remove the test script '/testssi.ssi'.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 summary["english"] = "Xitami XSS test";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! thorough_tests && "Xitami" >!< banner ) exit(0);


req = string("GET / HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"User-Agent: <script>foo</script>\r\n\r\n");

soc = http_open_socket(port);
if ( ! soc ) exit(0);

send(socket:soc, data:req);

r = http_recv(socket:soc);
if ( ! r ) exit(0);

r = strstr(r, '\r\n\r\n');
if ( ! r ) exit(0);

if ( "<script>foo</script>" >< r ) { security_note(port); exit(0); }
