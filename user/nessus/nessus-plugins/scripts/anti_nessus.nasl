#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#
########################

if(description)
{
 script_id(11238);
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "Anti Nessus defenses";
 name["francais"] = "Défenses anti Nessus";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It seems that your web server rejects requests 
from Nessus. It is probably protected by a reverse proxy.

Risk factor : None

Solution : change your configuration if you want accurate audit results";

 desc["francais"] = "
Il semble que votre serveur web rejette les requêtes
envoyées par Nessus. Il est probablement protégé par un 
relais. 


Facteur de risque : Aucun

Solution : Modifiez votre configuration 
           si vous voulez des tests exhaustifs";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detects anti Nessus features";
 summary["francais"] = "Détecte des fonctions anti Nessus";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi",
		francais:"Ce script est Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl");
 script_require_ports("Services/www",  80);
 exit(0);
}

#

include("global_settings.inc");
if (! experimental_scripts) exit(0); # Still broken?

include("http_func.inc");
##include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

no404 = get_kb_item(string("www/no404/", port));
rep = "It seems that your web server rejects requests 
from Nessus. It is probably protected by a reverse proxy.
";

if (no404)
 rep += "
However, the way the filter is implemented, it may in fact
help a script kiddy that uses Nessus to scan your system.


Risk factor : Low

Solution : change your configuration if you want accurate 
           audit results and a better protection";
else
  rep += "

Risk factor : None

Solution : change your configuration 
           if you want accurate audit results";

u = string("/NessusTest", rand(), ".html");
r = http_get(port: port, item: u);

c1 = http_send_recv(port:port, data:r);
if( c1 == NULL ) exit(0);
x1 = ereg_replace(pattern:"^HTTP/[0-9]\.[0-9] ([0-9][0-9][0-9]) .*$",
		string:c1, replace: "\1");
if (c1 == x1) x1 = "";

u = string("/", rand_str(), ".html");
r = http_get(port: port, item: u);

c2 = http_send_recv(port:port, data:r);
if(c2 == NULL)exit(0);
x2 = ereg_replace(pattern:"^HTTP/[0-9]\.[0-9] ([0-9][0-9][0-9]) .*$",
		string:c2, replace: "\1");
if (c2 == x2) x2 = "";

##display("x1=", x1, "\tx2=", x2, "\n");

if (x1 != x2)
{
  security_warning(port: port, data: rep);
  set_kb_item(name: string("www/anti-nessus/",port,"/rand-url"), value: TRUE);
  exit(0);
}


r = http_get(port: port, item: "/");
c1 = http_send_recv(port:port, data:r);
if(c1 == NULL)exit(0);
# Extract the HTTP code
c1 = egrep(pattern:"^HTTP/[0-9]\.[0-9] [0-9]* .*", string:c1);
x1 = ereg_replace(pattern:"^HTTP/[0-9]\.[0-9] ([0-9][0-9][0-9]) .*$",
		string:c1, replace: "\1");
if (c1 == x1) x1 = "";

#ua = '\nUser-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.3.1) Gecko/20030425\r\n';
ua = '\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\n';

r2 = ereg_replace(string: r, pattern: '\nUser-Agent:[^\r]*Nessus[^\r]*\r\n', replace: ua);
if (r == r2) exit(0);	# Cannot test

c2 = http_send_recv(port:port, data:r2);
if(c2 == NULL)exit(0);
# Extract the HTTP code
c2 = egrep(pattern:"^HTTP/[0-9]\.[0-9] [0-9]* .*", string:c2);
x2 = ereg_replace(pattern:"^HTTP/[0-9]\.[0-9] ([0-9][0-9][0-9]) .*$",
		string:c2, replace: "\1");
if (c2 == x2) x2 = "";

##display("x1=", x1, "\tx2=", x2, "\n");

if (x1 != x2)
{
  security_warning(port: port, data: rep);
  set_kb_item(name: string("www/anti-nessus/",port,"/user-agent"),value: ua);
  exit(0);
}

