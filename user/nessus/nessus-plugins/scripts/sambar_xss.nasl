#
# This script was written by Renaud Deraison
#
# GPL
#
# References:
# Date: 27 Mar 2003 17:26:19 -0000
# From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#

if(description)
{
 script_version ("$Revision: 1.7 $");
 script_id(11492);
 script_bugtraq_id(7209);
 script_name(english:"Sambar XSS");
 
 
 desc["english"] = "
The Sambar web server comes with a set of CGIs are that vulnerable
to a cross site scripting attack.

An attacker may use this flaw to steal the cookies of your web users.

Solution : Delete these CGIs
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for XSS attacks";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

cgis = make_list("/netutils/ipdata.stm?ipaddr=",
		 "/netutils/whodata.stm?sitename=",
		 "/netutils/finddata.stm?user=",
		 "/isapi/testisa.dll?check1=",
		 "/cgi-bin/environ.pl?param1=",
		 "/samples/search.dll?login=AND&query=",
		 "/wwwping/index.stm?wwwsite=",
		 "/syshelp/stmex.stm?bar=456&foo=",
		 "/syshelp/cscript/showfunc.stm?func=",
		 "/syshelp/cscript/showfnc.stm?pkg=",
		 "/sysuser/docmgr/ieedit.stm?path=",
		 "/sysuser/docmgr/edit.stm?path=",
		 "/sysuser/docmgr/iecreate.stm?path=",
		 "/sysuser/docmgr/create.stm?path=",
		 "/sysuser/docmgr/info.stm?path=",
		 "/sysuser/docmgr/ftp.stm?path=",
		 "/sysuser/docmgr/htaccess.stm?path=",
		 "/sysuser/docmgr/mkdir.stm?path=",
		 "/sysuser/docmgr/rename.stm?path=",
		 "/sysuser/docmgr/search.stm?path=",
		 "/sysuser/docmgr/sendmail.stm?path=",
		 "/sysuser/docmgr/template.stm?path=",
		 "/sysuser/docmgr/update.stm?path=",
		 "/sysuser/docmgr/vccheckin.stm?path=",
		 "/sysuser/docmgr/vccreate.stm?path=",
		 "/sysuser/docmgr/vchist.stm?path=",
		 "/cgi-bin/testcgi.exe?");
		 
report = NULL;

foreach c (cgis)
{
 req = http_get(item:c+"<script>foo</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if("<script>foo</script>" >< res)
 {
  report += c + '<script>code</script>\n';
 }
}


if ( report != NULL )
{
 text = "
The following Sambar default CGIs are vulnerable to a cross-site scripting
attack. An attacker may use this flaw to steal the cookies of your
users :

" + report + "

Solution : Delete these CGIs.
Risk factor : Medium";

 security_warning(port:port, data:text);
}
