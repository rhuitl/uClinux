#
# (C) Tenable Network Security
#


if(description)
{
  script_id(15775);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2004-1536");
  script_bugtraq_id(11719);

  name["english"] = "Invision Power Board Arcade SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection vulnerability.

Description :

The installation of Invision Power Board on the remote host includes
an optional module, named 'Arcade', that allows unauthorized users to
inject SQL commands into the remote SQL database through the 'cat'
parameter.  An attacker may use this flaw to gain control of the
remote database and possibly to overwrite files on the remote host. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2004-11/0264.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Board Arcade SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("invision_power_board_detect.nasl");
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
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];

 req = http_get(item:string(path, "/index.php?act=Arcade&cat=1'"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if ("mySQL query error: SELECT g.*, c.password FROM ibf_games_list AS" >< res)
  security_warning(port);
}
