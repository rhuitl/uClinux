#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains PHP scripts that allow copying of
arbitrary files into the web document directory. 

Description :

The remote host is running Limbo CMS, a content-management system
written in PHP. 

The 'com_fm' component of the version of Limbo installed on the remote
host allows an unauthenticated remote attacker to copy arbitrary
files, possibly taken from a third-party host, into the web document
directory.  An unauthenticated attacker may be able to exploit this
flaw to read files on the affected host or even set up a PHP shell
that would allow execution of arbitrary code, subject to the
privileges of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/446142/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22408);
  script_version("$Revision: 1.1 $");

  script_name(english:"Limbo com_fm Component PHP Shell Vulnerability");
  script_summary(english:"Tries to call Limbo's com_fm installer");

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
if (thorough_tests) dirs = make_list("/limbo", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Our exploits won't actually replace the 'fm.english.php' script; instead,
  # we just hope to see an error. This could lead to a false-positive if the
  # web user id can't actually write to 'fm.english.php'.
  bogus_dir = string(SCRIPT_NAME, "-", unixtime());
  if (thorough_tests) exploits = make_list(
    string(
      dir, "/admin/components/com_fm/fm.install.php?",
      "lm_absolute_path=../../../&",
      "install_dir=", bogus_dir
    ),
    string(
      dir, "/components/com_fm/fm.install.php?",
      "lm_absolute_path=../../&",
      "install_dir=", bogus_dir
    )
  );
  else exploits = make_list(
    string(
      dir, "/admin/components/com_fm/fm.install.php?",
      "lm_absolute_path=../../../&",
      "install_dir=", bogus_dir
    )
  );

  foreach exploit (exploits)
  {
    req = http_get(item:exploit, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see an error with our bogus directory name.
    if (string("copy(", bogus_dir, "/fm.english.php): failed to open stream") >< res)
    {
      security_warning(port);
      exit(0);
    }
  }
}
