# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# GPL
#
# References:
# Date:  Wed, 12 Sep 2001 04:36:22 -0700 (PDT)
# From: "ByteRage" <byterage@yahoo.com>
# Subject: EFTP Version 2.0.7.337 vulnerabilities
# To: bugtraq@securityfocus.com
# 

if(description)
{
  script_id(11093);
  script_bugtraq_id(3331, 3333);
  script_version("$Revision: 1.8 $");
  script_cve_id("CVE-2001-1109");
 name["english"] = "EFTP installation directory disclosure ";
 name["francais"] = "EFTP révèle le répertoire d'installation";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote FTP server can be used to determine the
installation directory by sending a request on an
unexisting file.

An attacker may use this flaw to gain more knowledge about
this host, such as its filesystem layout. 

Solution : update your FTP server
Risk factor : Low";
 


 desc["francais"] = "
Le serveur FTP distant peut révéler son répertoire 
d'installation en répondant à une requête sur un
fichier non existant.

Un pirate peut utiliser ce problème pour obtenir
plus d'informations sur ce système, comme la hiérarchie
de fichiers mise en place.

Solution : mettez votre serveur FTP à jour
Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "EFTP installation directory disclosure";
 summary["francais"] = "EFTP révèle son répertoire d'installation";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 family["english"] = "FTP";
 family["francais"] = "FTP";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
 exit(0);
}

#
include("ftp_func.inc");

cmd[0] = "GET";
cmd[1] = "MDTM";

port = get_kb_item("Services/ftp");
if(!port)port = 21;
login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");
# login = "ftp"; pass = "test@test.com";

if (!login) login = "ftp";
if (!pass) pass = "nessus@nessus.com";

if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

if( ftp_authenticate(socket:soc, user:login, pass:pass))
{
  for (i = 0; i < 2; i=i+1)
  {
    req = string(cmd[i], " nessus", rand(), "\r\n");
    send(socket:soc, data:req);
    r = ftp_recv_line(socket:soc);
    if (egrep(string:r, pattern:" '[C-Z]:\\'"))
    {
      security_warning(port);
      ftp_close(socket:soc);
      exit(0);
    }
  }
}
