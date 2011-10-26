#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
#

if(description)
{
 script_id(10129);
 script_bugtraq_id(1443, 616, 687);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0705","CVE-1999-0043","CVE-1999-0247");
 name["english"] = "INN version check";
 name["francais"] = "Vérification de la version de INN";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote version of INN is older
than version 1.6. 

A lot of security holes have been found
older versions of INN. You should upgrade
to avoid any trouble.


Solution : upgrade to version 1.6 or newer.

Risk factor : High";

 desc["francais"] = "
La version de INN est plus vieille que la
version 1.6.

Un grand nombre de trous de sécurité
ont été trouvés dans les vieilles
versions de INN. Vous devriez le
mettre à jour.

Solution : Mettez INN à jour en version 1.6
ou plus récente.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks INN version";
 summary["francais"] = "Vérifie la version d'INN";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

#
# The script code starts here
#



# Read the banner from the knowledge base,
# or get it by connecting to the server
# manually


port = get_kb_item("Services/nntp");
if(!port)port = 119;

key = string("nntp/banner/", port);
banner = get_kb_item(key);

if(!banner)
{
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
   banner = recv_line(socket:soc,length:1024);
   close(soc);
  }
 }
}



if(!banner)exit(0);
s = strstr(banner,"INN");
 if(s)
 {
  version = s[4];
  subversion = s[6];
  if((version == 1)&&(subversion < 6))
	{ security_hole(port); }

 }

