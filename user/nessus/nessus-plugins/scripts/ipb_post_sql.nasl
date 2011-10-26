#
# (C) Tenable Network Security
#


if(description)
{
  script_id(15778);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2004-1531");
  script_bugtraq_id(11703);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"11929");

  name["english"] = "Invision Power Board Post SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
a SQL injection attack. 

Description :

The version of Invision Power Board on the remote host suffers from a
flaw in 'sources/post.php' that allows injection of SQL commands into
the remote SQL database.  An attacker may use this flaw to gain
control of the remote database and possibly to overwrite files on the
remote host. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2004-11/0233.html
http://forums.invisionpower.com/index.php?showtopic=154916

Solution : 

Replace the 'sources/post.php' file with the one referenced in the
vendor advisory above. 

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Board Post SQL Injection";
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

 req = http_get(item:string(path, "/index.php?act=Post&CODE=02&f=3&t=10&qpid=1'"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ("mySQL query error: select p.*,t.forum_id FROM ibf_posts p LEFT JOIN ibf_topics t ON (t.tid=p.topic_id)" >< res)
  security_warning(port);
}
