#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10757);
 script_version ("$Revision: 1.11 $");
# script_cve_id("CVE-MAP-NOMATCH");
 name["english"] = "Check for Webmin";
 name["francais"] = "Vérifie la présence de Webmin";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote server is running Webmin.
Webmin is a web-based interface for system administration for Unix.

Solution: Stop Webmin service if not needed or configure the access
See menu [Webmin Configuration][IP Access Control]
and/or [Webmin Configuration][Port and Address]

For more info see http://www.webmin.net/
Risk factor : Medium";



 desc["francais"] = "
Le serveur distant fait tourner Webmin.
Webmin est une interface web d'administration Unix.

Solution: Arretez le service Webmin si il n'est pas desire ou configurez l'accès
Voir menu [Configuration de Webmin][Contrôle d'accès par adresses IP]
et/ou [Configuration de Webmin][Port et Adresse]

Pour plus d'info voir http://www.webmin.net/
Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Check for Webmin";
 summary["francais"] = "Vérifie la présence de Webmin";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com",
                francais:"Ce script est Copyright (C) 2001 Alert4Web.com");
 family["english"] = "Useless services";
 family["francais"] = "Services inutiles";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 10000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:10000);

foreach port (ports)
{
 banner = get_http_banner(port:port);

 if(banner)
 {
  if(egrep(pattern:"^Server: MiniServ.*",string:banner))
  {
     banner = http_keepalive_send_recv(port:port, data:http_get(item:"/",port:port));
     if(banner != NULL ) {
     if(egrep(pattern:"webmin", string:banner, icase:TRUE))
     {
     set_kb_item(name:"www/" + port + "/webmin", value:TRUE);
     security_warning(port);
     version = ereg_replace(pattern:".*Webmin *([0-9]\.[0-9][0-9]).*$",
    			    string:banner,
			    replace:"\1");
     if (version == banner) version = 0;
     if (version)
     {
       security_note(port:port, data:string("The Webmin version is : ", version));
       set_kb_item(name:"webmin/" + port + "/version",value:version); 
     }
    }
   }
  }
 }
}
