#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# Thanks to Jari Helenius <jari.helenius@mawaron.com>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10557);
 script_bugtraq_id(1589, 1993);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0738", "CVE-2000-1130");


 name["english"] = "WebShield";
 name["francais"] = "WebShield";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote WebShield server is subject to two flaws :

	- It may let mail pass against some filter rules if the
	  attached files names have some strange chars in them
	- It is possible for an outsider to crash this program
	  and force its reinstallation
	  
*** Nessus did not actually test for these flaws - it just relied
*** on the banner to identify them. Therefore, this warning may be
*** a false positive

Solution : None yet
Risk factor : High";

 desc["francais"] = "
Le serveur WebShield distant est sujet à deux problèmes de sécurité :

	- Il peut laisser les attachements si les noms fichiers attachés
	  contiennent des caractères étranges
	- Un pirate peut faire planter ce service à distance et
	  forcer sa réinstallation
	 
*** Nessus ne s'est fié qu'a la bannière de ce service, donc il 
*** s'agit peut etre d'une fausse alerte

Solution : aucune
Facteur de risque : Elevé";




 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the remote banner";
 summary["francais"] = "Vérfie la bannière distante";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped");
 script_require_ports("Services/smtp", 25);
 exit(0);
}


include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = smtp_recv_banner(socket:soc);

# MR1 not vulnerable
# http://www.nai.com/common/media/mcafeeb2b/support/WSHSMTP-MR1readme.txt


  if(egrep(string:r, pattern:"^220.*WebShield.*V4\.5 MR1[a-z] .*"))exit(0);

  if(egrep(string:r,
	pattern:"^220 .* WebShield SMTP V(([1-3]\..*)|(4\.[0-5])) .*$"))
		security_hole(port);
  }
}
