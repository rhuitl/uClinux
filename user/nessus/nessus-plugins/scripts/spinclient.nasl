#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Thanks to Tollef Fog Heen <tfheen@opera.no> for his help

if(description)
{
 script_id(10393);
 script_version ("$Revision: 1.14 $");

 name["english"] = "spin_client.cgi buffer overrun";
 name["francais"] = "spin_client.cgi buffer overrun";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
There is a buffer overrun in
the 'spin_client.cgi' CGI program, which will allow anyone to
execute arbitrary commands with the same privileges as the
web server (root or nobody).

Solution : remove it from /cgi-bin or contact
your vendor for a fix

Risk factor : High";


 desc["francais"] = "Il y a un dépassement de buffer
dans le CGI 'spin_client.cgi', qui permet à n'importe qui d'executer
des commandes arbitraires avec les memes privilèges que le 
serveur web (root ou nobody).

Solution : retirez-le de /cgi-bin ou contactez votre vendeur
pour un patch

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the /cgi-bin/spin_client.cgi buffer overrun";
 summary["francais"] = "Vérifie le dépassement de buffer de /cgi-bin/spin_client.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# This CGI is tricky to check for.
# 
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(item:string(dir, "/spin_client.cgi"), port:port))
 {
 soc = open_sock_tcp(port);
 if(soc)
 {
  req = string("GET ", dir, "/spin_client.cgi?",crap(8)," HTTP/1.0\r\n");
  req = req + string("User-Agent: ", crap(8), "\r\n\r\n");
  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:1024);
  close(soc);
  if(ereg(pattern:"^HTTP\/[0-9]\.[0-9] 200 ",
   	  string:r))
   {
   soc = open_sock_tcp(port);
   req = string("GET ", dir, "/spin_client.cgi?",crap(8000), " HTTP/1.0\r\n");
   req = req + string("User-Agent: ", crap(8000), "\r\n\r\n");
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   if(ereg(pattern:"^HTTP\/[0-9]\.[0-9] 500 ",
   	  string:r))
   {
   	security_hole(port);
   }
  }
 }
 else exit(0);
 }
}
