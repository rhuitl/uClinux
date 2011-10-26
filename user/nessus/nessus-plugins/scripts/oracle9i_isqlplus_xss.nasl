#
# This script was written by Frank Berger <dev.null@fm-berger.de>
# <http://www.fm-berger.de>
#
# This vulnerability was found by 
# Rafel Ivgi, The-Insider <theinsider@012.net.il>
#
# License: GPL v 2.0  http://www.gnu.org/copyleft/gpl.html
#
#

if(description)
{
 script_id(12112);
 script_version("$Revision: 1.6 $");
 name["english"] = "Oracle 9iAS iSQLplus XSS";
 name["francais"] = "Oracle 9iAS iSQLplus XSS";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

The login-page of Oracle9i iSQLplus allows the injection of HTML and Javascript
code via the username and password parameters.


Description :


The remote host is running a version of the Oracle9i 'isqlplus' CGI which
is vulnerable to a cross site scripting issue.

An attacker may exploit this flaw to to steal the cookies of legitimate 
users on the remote host.


See also : 

http://www.securitytracker.com/alerts/2004/Jan/1008838.html

Risk factor :

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Test for the possibility of an Cross-Site-Scripting XSS Attack in Oracle9i iSQLplus";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Frank Berger",
		francais:"Ce script est Copyright (C) 2004 Frank Berger");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(get_port_state(port))
{ 
 req = http_get(item:"/isqlplus?action=logon&username=foo%22<script>foo</script>&password=test", port:port);	      
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);
 if( '<script>foo</script>' >< res )	
 	security_warning(port);
}
