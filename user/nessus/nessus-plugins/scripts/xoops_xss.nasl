# This script was written by Renaud Deraison
#
# Ref :
#  Date: 1 Apr 2003 13:08:28 -0000
#  From: magistrat <magistrat@blocus-zone.com>
#  To: bugtraq@securityfocus.com
#  Subject: Css in Xoops module glossary 1.3.x

#
# This check will incidentally cover other flaws.

if(description)
{
 script_id(11508);
 script_bugtraq_id(7356);
 script_version ("$Revision: 1.11 $");

 name["english"] = "Xoops XSS";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to cross-
site scripting attacks. 

Description :

There is a cross site scripting issue in the version of Xoops
installed on the remote host that may allow an attacker to steal your
users cookies. The flaw lies in 'glossaire-aff.php'.

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=104931621609932&w=2

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";
 script_description(english:desc["english"]);

 summary["english"] = "Checks for Xoops";

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("xoops_detect.nasl", "cross_site_scripting.nasl");
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
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];

 req = http_get(item:string(d, "/modules/glossaire/glossaire-aff.php?lettre=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);

 if(egrep(pattern:"<script>foo</script>", string:res)){
 	security_note(port);
	exit(0);
 }
}
