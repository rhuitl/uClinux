#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: aCiDBiTS <acidbits@hotmail.com>
# This script is released under the GNU GPLv2


if(description)
{
 script_id(14269);
 script_bugtraq_id(10891);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8657");
   script_xref(name:"OSVDB", value:"8658");
 }
 script_version ("$Revision: 1.9 $");
 name["english"] = "YaPiG Remote Server-Side Script Execution Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to
arbitrary PHP code injection vulnerabilities. 

Description :

The remote host is running YaPiG, a web-based image gallery written in
PHP. 

The remote version of YaPiG may allow a remote attacker to execute
malicious scripts on a vulnerable system.  This issue exists due to a
lack of sanitization of user-supplied data.  It is reported that an
attacker may be able to upload content that will be saved on the
server with a '.php' extension.  When this file is requested by the
attacker, the contents of the file will be parsed and executed by the
PHP engine, rather than being sent.  Successful exploitation of this
issue may allow an attacker to execute malicious script code on a
vulnerable server. 

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0756.html

Solution :

Upgrade to YaPiG 0.92.2 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for YaPiG version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
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
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9][^0-9]|9([01]|2[ab]))", string:res))
 	{
 		security_hole(port);
		exit(0);
	}
 
}
