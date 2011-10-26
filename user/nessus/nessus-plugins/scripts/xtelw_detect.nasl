#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# I thought of putting both tests in a file, but that's quicker like this
# I think


if(description)
{
  script_id(11120);
#  script_cve_id("CVE-MAP-NOMATCH");
  script_version ("$Revision: 1.7 $");
 
  script_name(english:"xtelw detection", francais:"detection de xtelw");
 
  desc["english"] = "
xteld is running on this port in HyperTerminal mode. 
This service allows users to connect to the 'Teletel' network. 
Some of the servers are expensive. 
Note that by default, xteld forbids access to the most expensive 
services.

Risk factor : None";

  desc["francais"] = "
xteld tourne sur ce port en mode Hyperterminal.
Ce service permet de se connecter sur le réseau 'Télétel'. 
Certains des serveurs sont chers.
Notez que par défaut, xteld interdit l'accès aux serveurs les plus chers.

Risque : Aucun";


  script_description(english:desc["english"], francais:desc["francais"]);
 
  summary["english"] = "Detect xteld in HyperTerminal mode";
  summary["francais"] = "Détecte xteld en mode HyperTerminal";
  script_summary(english:summary["english"], francais:summary["francais"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
  script_family(english:"Service detection");
  script_dependencie("find_service.nes");
  script_require_ports("Services/unknown", 1314);

  exit(0);
}

#

include("misc_func.inc");

# Quick way
port=1314;
# Slow way
#port = get_kb_item("Services/unknown"); 
#if (! port) { port=1314; }

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

banner = get_unknown_banner(port: port, dontfetch:0);
if (! banner) exit(0);

# I'm too lazy to parse the service list :-)
if (("Service Minitel" >< banner) && ("Xteld" >< banner))
{
 security_note(port);
 register_service(port: port, proto: "xtelw");
}


