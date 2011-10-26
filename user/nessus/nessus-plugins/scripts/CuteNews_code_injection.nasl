#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# From: "Over_G" <overg@mail.ru>
# To: vuln@security.nnov.ru, bugtraq@securityfocus.com,
#        staff@packetstormsecurity.org
# Subject: PHP code injection in CuteNews
# Message-Id: <E18ndJT-000JS2-00@f19.mail.ru>



if(description)
{
 script_id(11276);
 script_cve_id("CVE-2003-1240");
 script_bugtraq_id(6935);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"5957");
   script_xref(name:"OSVDB", value:"6051");
   script_xref(name:"OSVDB", value:"6052");
 }
 script_version ("$Revision: 1.12 $");

 name["english"] = "CuteNews code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is subject to
multiple remote file include attacks. 

Description :

The version of CuteNews installed on the remote host fails to sanitize
input to the 'cutepath' parameter before using it in various scripts
to include PHP code.  An attacker may use this flaw to inject
arbitrary code in the remote host and gain a shell with the privileges
of the web server. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2003-02/0320.html

Solution : 

Upgrade to CuteNews 0.89 or newer.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of search.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2006 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003-2006 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("cutenews_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 req = http_get(item:string(loc, "/search.php?cutepath=http://xxxxxxxx"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/config\.php", string:r))
 {
 	security_note(port);
	exit(0);
 }
}
