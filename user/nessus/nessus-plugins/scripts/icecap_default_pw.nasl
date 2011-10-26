#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to RFP for his explanations.
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10410);
 script_bugtraq_id(1216);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0350");
 name["english"] = "ICEcap default password";
 name["francais"] = "Mot de passe par défaut de ICEcap";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The ICEcap package has a default login
of 'iceman' with no password.

An attacker may use this fact to log into
the console and/or push false alerts
on port 8082.

In addition to this, an attacker may inject code
in ICEcap v2.0.23 and below. 


Solution : Set a password. If you are running version <= 2.0.23
of ICEcap, go to http://advice.networkice.com/advice/Support/KB/q000166/
Risk factor : High";




 desc["francais"] = "
Le program ICEcap vient avec un login par
défaut 'iceman' sans mot de passe.

Un pirate peut utiliser ce problème pour se logguer
sur la console distante et/ou envoyer de fausses
alertes sur le port 8082.

De plus, un pirate peut injecter des commandes dans 
les versions <= 2.0.23 de ICEcap.


Solution : mettez un mot de passe. Si vous utilisez ICEcap 2.0.23
ou plus ancien, allez sur http://advice.networkice.com/advice/Support/KB/q000166/
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "logs into the remote ICEcap subsystem";
 summary["francais"] = "se log dans le système ICEcap distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ICEcap", 8082);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/ICEcap");
if(!port)port = 8082;

if(get_port_state(port))
{
    code = http_get_cache(item:"/", port:port);
    if(code && ereg(string:code, pattern:"^HTTP/[0-9]\.[0-9] 401 .*"))
    {
     soc = open_sock_tcp(port);
     s = http_get(item:"/", port:port);
     s = s - string("\r\n\r\n");
     s = s + 
     	string("\r\n") + 
        string("Authorization: Basic aWNlbWFuOiUzQjclQzYlRkU=\r\n\r\n");
     send(socket:soc, data:s);
     code = recv_line(socket:soc, length:1024);
    # r = http_recv(socket:soc);
     http_close_socket(soc);
     if(ereg(string:code, pattern:"^HTTP/[0-9]\.[0-9] 200 .*"))
      {
       security_hole(port);
      }
    }
}
   
   

