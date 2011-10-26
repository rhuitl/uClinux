#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
# ref: admin@batznet.com and Mustafa Can Bjorn
#

if(description)
{
script_id(21035);
script_bugtraq_id(15214, 16914);
script_cve_id("CVE-2005-3369", "CVE-2006-1094");
if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"20330");
  script_xref(name:"OSVDB", value:"23596");
}

script_version("$Revision: 1.4 $");
script_name(english:"Woltlab Burning Board SQL injection flaw");


desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is susceptible to SQL
injection attacks. 

Description:

The remote version of Burning Board includes an optional module, the
Database module, that fails to properly sanitize the 'fileid'
parameter of the 'info_db.php' script, which can be exploited to
launch SQL injection attacks against the affected host. 

See also:

http://www.securityfocus.com/archive/1/426583/30/0/threaded

Solution:

Unknown at this time. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

script_description(english:desc["english"]);

script_summary(english:"Checks SQL injection flaw in Woltlab Burning Board Database module");
script_category(ACT_ATTACK);
script_copyright(english:"This script is Copyright (C) 2006 David Maciejak");
script_family(english:"CGI abuses");

 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);


# Test any installs.
installs = get_kb_list(string("www/", port, "/burning_board*"));

if ( isnull(installs) ) exit(0);

installs = make_list(installs);

foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
	loc = matches[2];
	buf = http_get(item:string(loc,"/info_db.php?action=file&fileid=1/**/UNION/**/SELECT/**/"), port:port);
	r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
	if( r == NULL )exit(0);
	if(("Database error in WoltLab Burning Board" >< r) && ("Invalid SQL: SELECT * FROM" >< r))
	{
		security_warning(port);
		exit(0);
	}
  }
}

