#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18628);
 script_bugtraq_id(14099);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"11025");
 }
 script_version ("$Revision: 1.3 $");
 name["english"] = "YaPiG Password Protected Directory Access Flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to an
information disclosure flaw. 

Description :

The remote host is running YaPiG, a web-based image gallery written in
PHP. 

The remote version of this software contains a flaw that can let a
malicious user view images in password protected directories. 
Successful exploitation of this issue may allow an attacker to access
unauthorized images on a vulnerable server. 

See also :

http://sourceforge.net/tracker/index.php?func=detail&aid=842990&group_id=93674&atid=605076
http://sourceforge.net/tracker/index.php?func=detail&aid=843736&group_id=93674&atid=605076 

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

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
include("global_settings.inc");

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
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9]($|[^0-9])|9([0-3]|4[a-u]))", string:res))
 	{
 		security_note(port);
		exit(0);
	}
 
}
