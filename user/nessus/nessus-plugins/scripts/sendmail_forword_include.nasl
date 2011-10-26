#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11349);
 script_bugtraq_id(715);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-1999-0129");

 name["english"] = "Sendmail Group Permissions Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
The remote sendmail server, according to its version number,
allows local users to write to a file and gain group permissions
via a .forward or :include: file.

Solution : Install sendmail newer than 8.8.4 or install a vendor
supplied patch.

Risk factor : High (Local) / None (remote with no account)";

 script_description(english:desc["english"]);


 summary["english"] = "Checks the version number";
 summary["francais"] = "Vérification du numéro de série de sendmail";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Xue Yong Zhi",
 		  francais:"Ce script est Copyright (C) 2001 Xue Yong Zhi");

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
 #looking for Sendmail 8.8, 8.8.1-8.8.3
 if(egrep(pattern:".*sendmail[^0-9]*8\.(8|8\.[1-3])/.*", string:banner, icase:TRUE))
 	security_hole(port);
}
