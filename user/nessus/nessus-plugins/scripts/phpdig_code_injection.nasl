#
# (C) Tenable Network Security
#
#

if(description)
{
  script_id(12008);
  script_cve_id("CVE-2004-0068");
  script_bugtraq_id(9424);
  script_version("$Revision: 1.7 $");
  name["english"] = "phpdig Code injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running phpdig, an http search engine written in PHP.
There is a flaw in this product which may allow an attacker to execute
arbitrary PHP code on this by forcing this set of CGI to include a
PHP script hosted on a third party host.

Solution : Upgrade to the latest version of this software
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect phpdig code injection vuln";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);


function check_dir(path)
{
 req = http_get(item:string(path, "/includes/config.php?relative_script_path=http://xxxxxxx"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ("http://xxxxxxx/libs/.php" >< res ) 
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
check_dir(path:dir);
}
