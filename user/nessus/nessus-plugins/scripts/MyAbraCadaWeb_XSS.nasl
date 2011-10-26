#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# Message-ID: <20030317202237.3654.qmail@www.securityfocus.com>
# From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-010] Path Disclosure & Cross Site Scripting Vulnerability in MyABraCaDaWeb


if (description)
{
 script_id(11417);
 script_bugtraq_id(7126, 7127);
 script_version ("$Revision: 1.13 $");

 script_name(english:"MyAbraCadaWeb Cross Site Scripting");
 desc["english"] = "
Synopsis :

The remote web server contains a CGI which is vulnerable to a cross-site 
scripting and a path disclosure issue.

Description : 

The remote host seems to be running MyAbraCadaWeb. An attacker
may use it to perform a cross site scripting attack on this host, or 
to reveal the full path to its physical location by sending a malformed
request.


Solution : 

Upgrade to a newer version of this software

Risk factor : 

Low / CVSS Base Score : 3
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if a remote host is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = make_list(cgi_dirs());
		


foreach d (dir)
{
 url = "/index.php?module=pertinance&ma_ou=annuaire2liens&ma_kw=<script>alert(document.cookie)</script>";
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
 if ( "<script>alert(document.cookie)</script>" >< buf )
   {
    security_note(port:port);
    exit(0);
   }
}
