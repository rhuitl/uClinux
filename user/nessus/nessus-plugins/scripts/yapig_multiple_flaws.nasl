#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18523);
 script_cve_id("CVE-2005-1881", "CVE-2005-1882", "CVE-2005-1883", "CVE-2005-1884", "CVE-2005-1885", "CVE-2005-1886");
 script_bugtraq_id(13871, 13874, 13875, 13876, 13877);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"17115");
   script_xref(name:"OSVDB", value:"17116");
   script_xref(name:"OSVDB", value:"17117");
   script_xref(name:"OSVDB", value:"17118");
   script_xref(name:"OSVDB", value:"17119");
   script_xref(name:"OSVDB", value:"17120");
   script_xref(name:"OSVDB", value:"17121");
 }
 script_version ("$Revision: 1.6 $");
 name["english"] = "YaPiG Multiple Flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws. 

Description :

The remote host is running YaPiG, a web-based image gallery written in
PHP. 

The installed version of YaPiG is vulnerable to multiple flaws:

  - Remote and local file inclusion.
  - Cross-site scripting and HTML injection flaws through 'view.php'.
  - Directory traversal flaw through 'upload.php'.

See also :

http://secwatch.org/advisories/secwatch/20050530_yapig.txt

Solution : 

Update to YaPiG 0.95b or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for YaPiG version";
 
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/yapig", "/gallery", "/photos", "/photo", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
	res = http_get_cache(item:string(dir, "/"), port:port);
	if (res == NULL) exit(0);

	#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9]($|[^0-9])|9([0-4][a-z]|5a))", string:res))
 	{
 		security_hole(port);
		exit(0);
	}
 
}
