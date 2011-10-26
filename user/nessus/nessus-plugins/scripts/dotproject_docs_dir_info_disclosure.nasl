#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple information disclosure vulnerabilities. 

Description :

The remote host is running dotProject, a web-based, open-source,
project management application written in PHP. 

The installed version of dotProject discloses sensitive information
because it lets an unauthenticated attacker call scripts in the 'docs'
directory. 

See also :

http://www.securityfocus.com/archive/1/424957/30/0/threaded
http://www.dotproject.net/vbulletin/showthread.php?t=4462

Solution :

Remove the application's 'doc' directory. 

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


if (description) {
  script_id(20926);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0756");

  script_name(english:"dotProject docs Directory Information Disclosure Vulnerabilities");
  script_summary(english:"Checks for docs directory information disclosure vulnerabilities in dotProject");
 
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
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
if (thorough_tests) dirs = make_list("/dotproject", "/dotProject", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # It's dotProject if...
  if (
    # it looks like dotProject's index.php or...
    ' alt="dotProject logo"' >< res ||
    # it hasn't been installed yet.
    (
      "<meta http-equiv='refresh' content='5;" >< res &&
      "Click Here To Start Installation and Create One!" >< res
    )
  ) {
    # Try to run the application's phpinfo.php script.
    req = http_get(item:string(dir, "/docs/phpinfo.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< res) {
      security_note(port);
      exit(0);
    }
  }
}
