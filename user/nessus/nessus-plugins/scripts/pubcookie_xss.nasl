#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21158);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1392");
  script_bugtraq_id(17221);
  script_xref(name:"OSVDB", value:"24521");

  script_name(english:"Pubcookie Login Server Cross-Site Scripting Vulnerabilities");
  script_summary(english:"Tries to inject arbitrary script into Pubcookie Login Server");

  desc = "
Synopsis :

The remote web server contains a CGI script that is affected by
several non-persistent cross-site scripting flaws. 

Description :

The remote host is running Pubcookie, an open-source package for
intra-institutional single-sign-on end-user web authentication. 

The version of the Login Server component of Pubcookie installed on
the remote host fails to sanitize user-supplied input to various
parameters of the 'index.cgi' script before using it to generate
dynamic HTML.  An attacker may be able to exploit these issues to
cause arbitrary HTML and script code to be executed by a user's
browser in the context of the affected web site, which could be used
to steal authentication credentials or mis-represent the affected
application. 

See also :

http://pubcookie.org/news/20060306-login-secadv.html

Solution :

Upgrade to Pubcookie version 3.2.1b / 3.3.0a or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
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
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";


# Loop through various directories.
if (thorough_tests) dirs = make_list("/pubcookie", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws.
  req = http_get(
    item:string(
      dir, "/login?",
      'user=">', urlencode(str:xss)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our XSS.
  if (
    xss >< res &&
    egrep(pattern:'type="hidden" name="(pre_sess_tok|first_kiss|pinit|create_ts)"', string:res)
  )
  {
    security_note(port);
    exit(0);
  }
}
