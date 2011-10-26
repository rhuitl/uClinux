#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10014);
 script_bugtraq_id(770);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0885");
 name["english"] = "tst.bat CGI vulnerability";
 name["francais"] = "tst.bat";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'tst.bat' CGI script is installed on this 
 machine. This CGI has a well known security flaw that would allow 
 an attacker to  read arbitrary files on the remote system.

Solution : Remove the 'tst.bat' script from your web server's CGI
directory (typically cgi-bin/).

Risk factor : High";


 desc["francais"] = "Le cgi 'tst.bat' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de
lire des fichiers arbitraires sur le système.

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/tst.bat";
 summary["francais"] = "Vérifie la présence de /cgi-bin/tst.bat";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(req, exp)
{
  req = http_get(item:req, port:port);
  b = http_keepalive_send_recv(port:port, data:req);
  if( b == NULL ) exit(0);
  if(exp >< b)return(1);
  return(0); 
}

foreach dir (cgi_dirs())
{
 item1 = string(dir, "/tst.bat|type%20c:\\windows\\win.ini");
 item2 = string(dir, "/tst.bat|type%20c:\\winnt\\win.ini");
 if(check(req:item1, exp:"[windows]"))
 {
  security_hole(port);
  exit(0);
 }
 if(check(req:item2, exp:"[fonts]"))
 {
  security_hole(port);
  exit(0);
 }
}
