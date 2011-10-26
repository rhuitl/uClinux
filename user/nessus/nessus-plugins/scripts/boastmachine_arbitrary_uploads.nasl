#
# (C) Tenable Network Security
#


if (description) {
  script_id(18247);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1580");
  script_bugtraq_id(13600);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"16334");

  name["english"] = "boastMachine Remote Arbitrary File Upload Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by an
arbitrary file upload vulnerability. 

Description :

The remote host is running boastMachine, an open-source publishing
tool written in PHP. 

According to its banner, the version of boastMachine installed on the
remote host allows authenticated users to upload arbitrary files and
then run them subject to the privileges of the web server user. 

See also :

http://www.kernelpanik.org/docs/kernelpanik/bmachines.txt
http://boastology.com/pages/changes.php

Solution : 

Upgrade to boastMachine version 3.1 or later. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote arbitrary file upload vulnerability in boastMachine";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for boastMachine.
foreach dir (cgi_dirs()) {
  # Grab index.php.
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # Check the banner.
  if (
    # v3.x banners.
    res =~ "Powered by.*http://boastology.com.*v3\.0 platinum" ||
    # v2.x banners span several lines.
    (
      res =~ 'by <a href="http://boastology.com".+>BoastMachine</font></a>' &&
      res =~ "^  v [0-2]\.[0-9]+  <br>$"
    )
  ) {
    security_warning(port);
    exit(0);
  }
}
