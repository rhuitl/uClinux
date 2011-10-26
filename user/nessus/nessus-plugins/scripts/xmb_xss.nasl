#
# (C) Renaud Deraison
#

if (description)
{
 script_id(11527);
 script_bugtraq_id(4167, 4944, 8013);
 script_cve_id("CVE-2002-0316", "CVE-2003-0375", "CVE-2003-0483");
 script_version ("$Revision: 1.15 $");

 script_name(english:"XMB Cross Site Scripting");
 desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to
multiple cross-site scripting flaws. 

Description :

The remote host is running XMB Forum, a web forum written in PHP.

The version of XMB installed on the remote host is affected by several
cross-site scripting issues. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=101447886404876&w=2
http://www.securitybugware.org/Other/5409.html
http://marc.theaimsgroup.com/?l=bugtraq&m=105638720409307&w=2
http://marc.theaimsgroup.com/?l=bugtraq&m=105363936402228&w=2

Solution: 

Upgrade to XMB 1.9.1 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if XMB forums is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);

if (thorough_tests) dirs = make_list("/xmb", "/forum", "/forums", "/board", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 url = string(dir, '/buddy.php?action=<script>x</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "<script>x</script>" >< buf)
   {
    security_note(port);
    exit(0);
   }

 if (thorough_tests) {

  url = string(dir, '/forumdisplay.php?fid=21"><script>x</script>');
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
  if( buf == NULL ) exit(0);

  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
     "<script>x</script>" >< buf)
    {
     security_note(port);
     exit(0);
    }

  url = string(dir, '/admin.php?action=viewpro&member=admin<script>x</script>');
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
  if( buf == NULL ) exit(0);

  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
     "<script>x</script>" >< buf)
    {
     security_note(port);
     exit(0);
    }
 }
}
