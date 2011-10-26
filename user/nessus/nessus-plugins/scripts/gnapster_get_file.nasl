#
# Copyright (C)2000 Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10408);
 script_bugtraq_id(1186);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0412");
 name["english"] = "Insecure Napster clone";
 name["francais"] = "Clone Napster non sur";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
An insecure Napster clone is running on the
remote computer, which allows an intruder to
read arbitrary files on this system.

Solution : block incoming connections to this port,
or update your clone client.
Risk factor : High";




 desc["francais"] = "
Un clone non sécurisé de Napster tourne sur ce
port et permet à n'importe qui de lire des
fichiers aribitraires sur ce système.

Solution : bloquez les connections sur ce port, ou
mettez à jour votre client.
Facteur de risque : Elevé";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Detect the presence of a Napster client clone";
 summary["francais"] = "Detecte la présence d'un clone du client Napster";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);

 script_require_keys("Services/napster");
 script_require_ports("Services/napster", 6699);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#

 port = get_kb_item("Services/napster");
 if (!port) port = 6699;

 if (get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
    r = recv(socket:soc, length:1024);
    send(socket:soc, data:"GET");
    str = string("Nessus ", raw_string(0x22), "\\etc\\passwd", raw_string(0x22), " 9");
    send(socket:soc, data:str);
    r = recv(socket:soc, length:4096);
    if("root:" >< r)
    {
     security_hole(port);
    }
    close(soc);
  }
 }
