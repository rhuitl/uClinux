#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10143);
 script_bugtraq_id(591);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0753");
 name["english"] = "MSQL CGI overflow";
 name["francais"] = "Dépassement de buffer dans le CGI msql";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It seems possible to overflow the remote MSQL cgi
by making a request like :

	GET /cgi-bin/w3-msql/AAAA...AAAA
	
This allows an attacker to execute arbitrary code
as the httpd server (nobody or root).

Solution : remove this CGI.

Risk factor : High";
	

 desc["francais"] = "
Il semble possible de faire un dépassement de buffer
dans le CGI distant 'msql' en faisant la requête :

	GET /cgi-bin/w3-msql/AAAAA...AAAA
	
Ce problème peut permettre à un pirate d'executer du
code arbitraire avec les memes droits que le serveur
web (nobody ou root).

Solution : retirez ce CGI.

Facteur de risque : Elevé";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflows the remote CGI buffer";
 summary["francais"] = "Dépassement de buffer dans le CGI distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 if(!ereg(pattern:".*\.nsf/.*", string:dir))
 {
 str = http_get(item:string(dir, "/w3-msql/"), port:port);	 
 buf = http_keepalive_send_recv(port:port, data:str);
 if(!buf)exit(0);
 buf = tolower(buf);
 if("internal server error" >< buf)
   exit (0);

 str = http_get(item:string(dir, "/w3-msql/", crap(250)),
  		 port:port);	 
 buf = http_keepalive_send_recv(port:port, data:str);
 if(!buf)exit(0);
 buf = tolower(buf);
 if("internal server error" >< buf && 
    !egrep(string: buf, pattern: "w3-msql.* not found"))
 # egrep avoids false positive on Caucho Resin /servlet directory
 {
   security_hole(port);exit(0);
 }
 }
}
