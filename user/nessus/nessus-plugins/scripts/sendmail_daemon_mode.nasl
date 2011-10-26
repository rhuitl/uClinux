#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11346);
 script_bugtraq_id(716);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-1999-0130");

 name["english"] = "Sendmail 8.7.*/8.8.* local overflow";
 name["francais"] = "Dépassement de buffer local dans sendmail 8.7/8.8.*";
 script_name(english:name["english"],
 	     francais:name["francais"]);

 desc["english"] = "
The remote sendmail server, according to its version number,
allows local user to start it in daemon mode and gain root
privileges.

Solution : Install sendmail newer than 8.8.3 or install a vendor
supplied patch.

Risk factor : High (Local) / None (remote with no account)";

 script_description(english:desc["english"],
 	 	    francais:desc["francais"]);


 summary["english"] = "Checks the version number";
 summary["francais"] = "Vérification du numéro de série de sendmail";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Xue Yong Zhi",
 		  francais:"Ce script est Copyright (C) 2003 Xue Yong Zhi");

 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_require_keys("SMTP/sendmail");
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner)
{
 #looking for Sendmail 8.7.*, 8.8, 8.8.1, 8.8.2
 if(egrep(pattern:".*sendmail[^0-9]*8\.(7|7\.[0-9]+|8|8\.(1|2))/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
