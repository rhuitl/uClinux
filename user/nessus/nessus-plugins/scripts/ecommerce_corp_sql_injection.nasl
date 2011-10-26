#
# (C) Tenable Network Security
#
#
#

if(description)
{
  script_id(12062);
  script_cve_id("CVE-2004-0300", "CVE-2004-0301");
  script_bugtraq_id(9676, 9687);
  script_version("$Revision: 1.7 $");
  name["english"] = "Ecommerce Corp. Online Store Kit More.php Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Ecommerce Corportation Online Store Kit, a web
based e-commerce CGI suite.

A vulnerability has been discovered in the more.php file
that allows unauthorized users to inject SQL commands or to perform
cross-site scripting attackes.

An attacker may use this flaw to gain the control of the remote database

Solution : Upgrade to the latest version of this software.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "More.php MoSQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if (!get_port_state(port))exit(0);
if (!can_host_php(port:port))exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/more.php?id=1'"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if ( res == NULL ) exit(0);

 if ( "SELECT catid FROM catlink WHERE prodid=1" >< res )
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
 {
 	check_dir(path:dir);
 }
