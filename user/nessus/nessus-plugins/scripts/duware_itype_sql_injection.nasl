#
# (C) Tenable Network Security
#


if (description) {
  script_id(20253);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3976");
  script_bugtraq_id(15681);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21385");
  }

  script_name(english:"DUware iType Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for iType parameter SQL injection vulnerability in DUware");
 
  desc = "
Synopsis :

The remote web server has an ASP application that is affected by a SQL
injection flaw. 

Description :

The remote host is running an ASP application from DUware such as
DUamazon, DUarticle, DUclassified, DUdirectory, DUdownload, DUgallery,
DUnews or DUpaypal. 

The installed version of that application does not validate input to
the 'iType' parameter of the 'inc_type.asp' script before using it in
a database query.  An attacker may be able to leverage this issue to
manipulate SQL queries. 

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/amazon", "/articles", "/calendar", "/classified", "/directory", "/gallery", "/news", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/type.asp?",
      "iType='", SCRIPT_NAME
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error and our script name.
  if (
    "Syntax error" >< res &&
    egrep(pattern:string("_TYPE = ''", SCRIPT_NAME), string:res)
  ) {
    security_warning(port);
    exit(0);
  }
}
