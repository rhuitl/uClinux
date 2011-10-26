#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#



if(description)
{
  script_id(11121);
#  script_cve_id("CVE-MAP-NOMATCH");
  script_version ("$Revision: 1.6 $");
 
  script_name(english:"xtel detection", francais:"detection de xtel");
 
  desc["english"] = "
xteld is running on this port. This service allows users to
connect to the 'Teletel' network. Some of the servers are expensive.
Note that by default, xteld forbids access to the most expensive 
services.

Risk factor : None";

  desc["francais"] = "
xteld tourne sur ce port. Ce service permet de se connecter sur le 
réseau 'Télétel'. Certains des serveurs sont chers.
Notez que par défaut, xteld interdit l'accès aux serveurs les plus chers.

Risque : Aucun";


  script_description(english:desc["english"], francais:desc["francais"]);
 
  summary["english"] = "Detect xteld";
  summary["francais"] = "Détecte xteld";
  script_summary(english:summary["english"], francais:summary["francais"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
  script_family(english:"Service detection");
  script_dependencie("find_service.nes");
  script_require_ports("Services/unknown", 1313);

  exit(0);
}

#
include ("misc_func.inc");

function read_xteld(s)
{
  m = "";
  while (1)
  {
    r = recv(socket: s, length: 1);
    if (strlen(s) == 0) return (m);
    len = ord(r);
    if (len == 130) return (m);
    r1 = recv(socket: s, length: len);
    send(socket: s, data: raw_string(0x83));
    r = recv(socket: s, length: 1);
    if (strlen(s) == 0) return (m);
    len = ord(r);
    if (len == 130) return (m);
    r2 = recv(socket: s, length: len);
    send(socket: s, data: raw_string(0x82));
    m = string(m, r1, " - ", r2, "\n");
  }
}

req1 = raw_string(6) + "Nessus" + raw_string(0x82);

# Quick way
port=1313;

# Slow way
#port = get_kb_item("Services/unknown"); 
#if (! port) port=1313;

if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: req1);
m1 = read_xteld(s: soc);
close(soc);

if (m1)
{
  m2 = string(
"xteld tourne sur ce port. Ce service permet de se connecter sur le\n",
"réseau 'Télétel'. Certains des serveurs sont chers.\n",
"Voici les services autorisés ici :\n",
	m1,
"\nRisque : Aucun\n"); 
  security_note(port: port, data: m2);
  register_service(port: port, proto: "xtel");
}


