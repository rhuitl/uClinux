#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10758);
 script_version ("$Revision: 1.9 $");
# script_cve_id("CVE-MAP-NOMATCH");
 name["english"] = "Check for VNC HTTP";
 name["francais"] = "Check for VNC HTPP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote server is running VNC.
VNC permits a console to be displayed remotely.

Solution: Disable VNC access from the network by 
using a firewall, or stop VNC service if not needed.

Risk factor : Medium";



 desc["francais"] = "
Le serveur distant fait tourner VNC.
VNC permet d'acceder la console a distance.

Solution: Protégez l'accès à VNC grace à un firewall,
ou arretez le service VNC si il n'est pas desire.

Facteur de risque : Moyen";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Detects the presence of VNC HTTP";
 summary["francais"] = "Vérifie la présence de VNC HTTP";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com",
                francais:"Ce script est Copyright (C) 2001 Alert4Web.com");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 5800, 5801, 5802);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("misc_func.inc");

function probe(port)
{
 banner = get_http_banner(port:port);
 if(banner)
 {
  if (egrep(pattern:"vncviewer\.(jar|class)", string:banner, icase:TRUE))
  {
   security_warning(port);
   set_kb_item(name:"www/vnc", value:TRUE);
  }
 }
}


ports = add_port_in_list(list:get_kb_list("Services/www"), port:5800);
ports = add_port_in_list(list:ports, port:5801);
ports = add_port_in_list(list:ports, port:5802);

foreach port (ports)
{
  probe(port:port);
}

