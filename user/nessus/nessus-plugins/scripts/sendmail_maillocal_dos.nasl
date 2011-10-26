#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11351);
 script_bugtraq_id(1146);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2000-0319");

 name["english"] = "Sendmail mail.local DOS";
 script_name(english:name["english"]);

 desc["english"] = "
mail.local in the remote sendmail server, according to its 
version number, does not properly identify the .\n string 
which identifies the end of message text, which allows a 
remote attacker to cause a denial of service or corrupt 
mailboxes via a message line that is 2047 characters 
long and ends in .\n.

Solution : Install sendmail version 8.10.0 and higher, or install 
a vendor supplied patch.

Risk factor : High";

 script_description(english:desc["english"]);


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
 #looking for Sendmail 5.58,5,59, 8.6.*, 8.7.*, 8.8.*, 8.9.1, 8.9.3(icat.nist.gov)
 #bugtrap id 1146 only said 8.9.3, I guess it want to say 8.9.3 and older
 if(egrep(pattern:".*sendmail[^0-9]*(5\.5[89]|8\.([6-8]|[6-8]\.[0-9]+)|8\.9\.[1-3]|SMI-[0-8]\.)/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
