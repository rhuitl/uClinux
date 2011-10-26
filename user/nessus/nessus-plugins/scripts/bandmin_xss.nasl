#
# (C) Tenable Network Security
#
#
# Date: 28 May 2003 16:38:40 -0000
# From: silent needel <silentneedle@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: Bandmin 1.4 XSS Exploit


if(description)
{
 script_id(11672);
 script_bugtraq_id(7729);
 script_cve_id("CVE-2003-0416");
 script_version ("$Revision: 1.14 $");


 name["english"] = "Bandmin XSS";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote host contains a CGI which is vulnerable to a cross site scripting
issue.

Description :

The remote host is running the Bandmin CGI suite.

There is a cross site scripting issue in this suite which may allow an
attacker to steal your users cookies.

The flaw lies in the cgi bandwitdh/index.cgi


Solution : 

None at this time.  You are advised to remove this CGI.

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";




 script_description(english:desc["english"]);

 summary["english"] = "Checks for Bandmin";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (make_list(  cgi_dirs()))
{
 req = http_get(item:string(d, "/bandwidth/index.cgi?action=showmonth&year=<script>foo</script>&month=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) &&
    egrep(pattern:"<script>foo</script>", string:res)){
 	security_note(port);
	exit(0);
 }
}
