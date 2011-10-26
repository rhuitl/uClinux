#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21757);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3245");
  script_bugtraq_id(18663);

  script_name(english:"mvnForum activatemember Cross-Site Scripting Vulnerabilities");
  script_summary(english:"Checks for an XSS flaw in mvnForum's activatemember script");
 
  desc = "
Synopsis :

The remote web server contains a Java application that is affected by
several cross-site scripting issues. 

Description :

The remote host is running mvnForum, an open-source, forum application
based on Java J2EE. 

The version of mvnForum installed on the remote host fails to sanitize
user-supplied input to the 'activatecode' and 'member' parameters of
the 'activatemember' script before using it to generate dynamic web
content.  Successful exploitation of this issue may lead to the
execution of arbitrary HTML and script code in a user's browser within
the context of the affected application. 

See also :

http://pridels.blogspot.com/2006/06/mvnforum-xss-vuln.html

Solution :

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = string('"', "><script>alert('", SCRIPT_NAME, "')</script>");
exss = urlencode(str:xss);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/mvnforum", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  req = http_get(
    item:string(
      dir, "/activatemember?",
      "activatecode=&",
      "member=", urlencode(str:xss)
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like mvnForum and...
    'form action="activatememberprocess"' >< res &&
    # we see our XSS.
    string('name="member" value="', xss) >< res
  )
  {
    security_note(port);
    exit(0);
  }
}
