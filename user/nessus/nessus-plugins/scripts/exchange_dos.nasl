#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10558);
 script_bugtraq_id(1869);
 script_cve_id("CVE-2000-1006");
 script_version ("$Revision: 1.13 $");
 name["english"] = "Exchange Malformed MIME header";
 name["francais"] = "En-tete MIME mal formée";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote Exchange server seems to be vulnerable to a flaw that
lets malformed MIME headers crash it.

*** Nessus did not actually test for these flaws - it just relied
*** on the banner to identify them. Therefore, this warning may be
*** a false positive - especially since the banner DOES NOT CHANGE
*** if the patch has been applied

The full testing methodology is available at http://online.securityfocus.com/archive/1/144494

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-082.mspx
Risk factor : High";

 desc["francais"] = "
Le serveur Exchange distant semble etre vulnérable à un problème
qui permettrait à des entetes MIME mal formée de le faire planter.


*** Nessus ne s'est fié qu'a la bannière de ce service, donc il 
*** s'agit peut etre d'une fausse alerte - d'autant plus que
*** la banière de ce service ne CHANGE PAS si le patch a été appliqué

Solution :  http://www.microsoft.com/technet/security/bulletin/MS00-082.mspx
Facteur de risque : Elevé";




 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);
		    
 
 summary["english"] = "Checks the remote banner";
 summary["francais"] = "Vérifie la bannière distante";
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
 banner = get_smtp_banner(port:port);
 if(!banner)exit(0);
 if(ereg(string:banner,
	   pattern:".*Microsoft Exchange Internet Mail Service 5\.5\.((1[0-9]{0,3})|(2(([0-5][0-9]{2})|(6(([0-4][0-9])|(50\.(([0-1][0-9])|(2[0-1])))))))).*"))
		security_hole(port);

}
