#
# (C) Tenable Network Security
#

if (description)
{
 script_id(16095);
 script_cve_id("CVE-2005-0267", "CVE-2005-0268");
 script_bugtraq_id(12150);
 script_version("$Revision: 1.5 $");
 script_name(english:"FlatNuke Form Submission Input Validation Vulnerability");
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple vulnerabilities. 

Description :

The remote host is running FlatNuke, a content management system
written in PHP and using flat files rather than a database for its
storage. 

The remote version of this software is vulnerable to a form submission
vulnerability that may allow an attacker to execute arbitrary PHP
commands on the remote host. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110477752916772&w=2

Solution : 

Upgrade to FlatNuke version 2.5.2 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if FlatNuke is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for FlatNuke.
if (thorough_tests) dirs = make_list("/flatnuke", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir ( dirs )
{
res = http_get_cache(item:string(dir, "/index.php"), port:port);
if(res == NULL ) exit(0);

if ( 'Powered by <b><a href="http://flatnuke.sourceforge.net">' >< res )
{
 str = chomp(egrep(pattern:'Powered by <b><a href="http://flatnuke.sourceforge.net">', string:res));
 version = ereg_replace(pattern:".*flatnuke-([0-9.]*).*", string:str, replace:"\1");
 if ( dir == "" ) dir = "/";

 # nb: pages no longer seem to include a version number so don't rely on the
 #     KB entry at least until a more general detection plugin can be written.
 set_kb_item(name:"www/" + port + "/flatnuke", value: version + " under " + dir);

 if ( ereg(pattern:"^([0-1]\.|2\.([0-4]\.|5\.[0-1][^0-9]))", string:version) )
 	{
	security_hole ( port );
	exit(0);
	}
 }
}
