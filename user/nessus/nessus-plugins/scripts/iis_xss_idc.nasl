#
# This script was written by Geoffroy Raimbault <graimbault@lynx-technologies.com>
#
# www.lynx-technologies.com
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_version ("$Revision: 1.11 $");
 script_id(11142);
 script_bugtraq_id(5900);
 name["english"] = "IIS XSS via IDC error";
 name["francais"] = "IIS XSS via une erreur IDC";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
This IIS Server appears to be vulnerable to a Cross
Site Scripting due to an error in the handling of overlong requests on
an idc file. It is possible to inject Javascript
in the URL, that will appear in the resulting page.

Risk factor : Medium

See also : http://online.securityfocus.com/bid/5900
           http://www.ntbugtraq.com/default.asp?pid=36&sid=1&A2=ind0210&L=ntbugtraq&F=P&S=&P=1391
 ";

 script_description(english:desc["english"]);

 summary["english"] = "Tests for IIS XSS via IDC errors";
 summary["francais"] = "Test de la vulnérabilité XSS dans IIS via une erreur IDC";


script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 Geoffroy Raimbault/Lynx Technologies",
francais:"Ce script est Copyright (C) 2002 Geoffroy Raimbault/Lynx Technologies");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

# We construct the malicious URL with an overlong idc filename
filename = string("/<script></script>",crap(334),".idc");
req = http_get(item:filename, port:port);

r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
str="<script></script>";
if((str >< r)) security_warning(port);
