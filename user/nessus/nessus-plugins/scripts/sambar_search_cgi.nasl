#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
  script_id(10514);
  script_bugtraq_id(1684);
 script_version ("$Revision: 1.15 $");
  script_cve_id("CVE-2000-0835");
  
  name["english"] = "Directory listing through Sambar's search.dll";
  name["francais"] = "Listing du contenu d'un repertoire avec search.dll de Sambar";

  script_name(english:name["english"], francais:name["francais"]);
  desc["english"] = "

The 'search.dll' CGI which comes with Sambar server can be
used to obtain a listing of the remote web server directories
even if they have a default page such as index.html.

This allows an attacker to gain valuable information about the
directory structure of the remote host and could reveal the
presence of files which are not intended to be visible.

Solution : disable the search.dll CGI, or upgrade to Sambar 4.4b4
Risk factor : Low";

  desc["francais"] = "
Il est possible d'obtenir la liste du contenu des repertoires
distants accessibles par HTTP, plutot que leur fichier index.html,
en utilisant le module search.dll de Sambar.

 Ce problème permet à un pirate d'obtenir plus d'informations
sur la machine attaquée, ainsi que de découvrir la présence de
fichiers HTML cachés.

Solution : désactivez ce CGI ou mettez Sambar à jour en 4.4b4";

 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks the presence of search.dll";
 summary["francais"] = "Vérifie la présence de search.dll";
 script_summary(english:summary["english"], francais:summary["francais"]);
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
     	 	  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";

 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
  if(get_kb_item("www/no404/" + port))exit(0);
  soc = http_open_socket(port);
  if(soc)
  {

  req = http_get(item:"/search.dll?query=%00&logic=AND", port:port);
  send(socket:soc, data:req);
  result = recv_line(socket:soc, length:2048);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if("HTTP/1.1 200 " >< result)
   {
    quote = raw_string(0x22);
    expect = string("A HREF=", quote, "/");
    if(expect >< r)security_warning(port);
   }
  }
}
