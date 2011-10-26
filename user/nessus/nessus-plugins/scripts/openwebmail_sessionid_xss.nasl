#
# (C) Tenable Network Security
#


if (description) {
  script_id(19769);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2863");
  script_bugtraq_id(14771);

  name["english"] = "Open WebMail sessionid Parameter Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script which is vulnerable to a
cross site scripting attack.

Description :

The installed version of Open WebMail on the remote host is prone to
cross-site scripting attacks because it fails to sanitize user-
supplied input to the 'sessionid' parameter of the
'openwebmail-main.pl' script. 

See also :

http://online.securityfocus.com/archive/1/409692/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for sessionid parameter cross-site scripting vulnerability in Open WebMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("openwebmail_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/openwebmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # A simple alert.
  xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
  exss = urlencode(str:xss);

  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/openwebmail-main.pl?",
      'sessionid=">', exss
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (xss >< res) {
    security_note(port);
    exit(0);
  }
}
