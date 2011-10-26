#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15784);
 script_cve_id(
   "CVE-2004-1537", 
   "CVE-2004-1538",
   "CVE-2005-2683",
   "CVE-2005-3552",
   "CVE-2005-3553",
   "CVE-2005-3554",
   "CVE-2005-4424",
   "CVE-2006-0785",
   "CVE-2006-0786",
   "CVE-2006-1507",
   "CVE-2006-1773"
 );
 script_bugtraq_id(11725, 14629, 15354, 17291, 17467);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"20553");
   script_xref(name:"OSVDB", value:"20554");
   script_xref(name:"OSVDB", value:"20555");
   script_xref(name:"OSVDB", value:"20556");
   script_xref(name:"OSVDB", value:"20557");
   script_xref(name:"OSVDB", value:"20558");
   script_xref(name:"OSVDB", value:"20559");
   script_xref(name:"OSVDB", value:"20560");
   script_xref(name:"OSVDB", value:"20561");
   script_xref(name:"OSVDB", value:"20562");
   script_xref(name:"OSVDB", value:"20563");
 }

 script_version("$Revision: 1.11 $");
 name["english"] = "PHP-Kit Multiple Flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected 
by several issues.

Description :

The remote host is running PHP-Kit, an open-source content management
system written in PHP.

The remote version of this software is vulnerable to multiple remote and
local code execution, SQL injection and cross-site scripting flaws. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110117116115493&w=2
http://marc.theaimsgroup.com/?l=bugtraq&m=112474427221031&w=2
http://www.hardened-php.net/advisory_212005.80.html
http://retrogod.altervista.org/phpkit_161r2_incl_xpl.html
http://www.securityfocus.com/archive/1/429249/30/0/threaded

Solution : 

Remove the application as it is no longer maintained.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for SQL Injection in PHPKIT";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

loc = make_list();

# 1. Detect phpkit
if (thorough_tests) dirs = make_list("/phpkit", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 req = http_get(item:dir + "/include.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 line = egrep(pattern:".*PHPKIT.* Version [0-9.]*", string:res);
 if ( line )
 {
  version = ereg_replace(pattern:".*PHPKIT.* Version ([0-9.]*).*", string:line, replace:"\1");
  if ( version == line ) version = "unknown";
  if ( dir == "" ) dir = "/";

  set_kb_item(name:"www/" + port + "/phpkit", value:version + " under " + dir);
  loc = make_list(dir, loc);
 }
}

# Now check the SQL injection

foreach dir (loc)
{
 req = http_get(item:dir + "/popup.php?img=<script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if  ( 'ALT="<script>" SRC="<script>"' >< res ) 
	{
	security_warning(port);
	exit(0);
	}
 req = http_get(item:loc + "/include.php?path=guestbook/print.php&id='", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if  ( "SELECT * FROM phpkit_gbook WHERE gbook_id='''" >< res )
	{
	security_warning(port);
	exit(0);
	}
}
