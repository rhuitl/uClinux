#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21618);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2755");
  script_bugtraq_id(18152);

  script_name(english:"UBB.threads debug Parameter Cross-Site Scripting Vulnerability");
  script_summary(english:"Tries to exploit an XSS flaw in UBB.threads");

  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
cross- site scripting vulnerability. 

Description :

The version of UBB.threads installed on the remote host fails to
sanitize input to the 'debug' parameter before using it in the
'ubbthreads.php' script for dynamically-generated content.  Regardless
of any PHP settings, an unauthenticated attacker may be able to
exploit this flaw to inject arbitrary HTML and script code in a user's
browser in the context of the affected web site, resulting in theft of
authentication data or other such attacks. 

See also :

http://www.securityfocus.com/archive/1/435288/30/0/threaded
http://www.securityfocus.com/archive/1/435296/30/0/threaded

Solution :

Unknown at this time. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ubbthreads_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = string('<script>alert("', SCRIPT_NAME, '")</script>');
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  req = http_get(
    item:string(
      dir, "/ubbthreads.php?",
      "debug=", exss
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (string(xss, "</body>") >< res)
  {
    security_note(port);
    exit(0);
  }
}
