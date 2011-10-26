#
# (C) Tenable Network Security
#


if(description)
{
 script_id(12058);
 script_cve_id("CVE-2004-2076");
 script_bugtraq_id(9649, 9656);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "JelSoft VBulletin XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host contains a PHP application that is vulnerable to a
cross-site scripting attack. 

Description :

There is a cross-site scripting issue in vBulletin that may allow an
attacker to steal a user's cookies. 

See also :

http://www.securityfocus.com/archive/1/353869

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for JelSoft VBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security"); 
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("vbulletin_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 req = http_get(item:string(d, "/search.php?do=process&showposts=0&query=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if (res == NULL) exit(0);

 if ("<script>foo</script>" >< res) security_note(port);
}
