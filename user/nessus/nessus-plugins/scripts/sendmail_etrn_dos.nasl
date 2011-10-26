#
# This script was written by Xue Yong Zhi <xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11350);
 script_bugtraq_id(904);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-1999-1109");

 name["english"] = "Sendmail ETRN command DOS";
 script_name(english:name["english"]);

 desc["english"] = "
The remote sendmail server, according to its version number,
allows remote attackers to cause a denial of service by
sending a series of ETRN commands then disconnecting from
the server, while Sendmail continues to process the commands
after the connection has been terminated.

Solution : Install sendmail version 8.10.1 and higher, or 
install a vendor supplied patch.

Risk factor : Medium";

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
 #looking for Sendmail 8.10.0 and previous
 if(egrep(pattern:".*sendmail[^0-9]*(SMI-)?8\.([0-9]|[0-9]\.[0-9]+|10\.0)/.*", string:banner, icase:TRUE))
 	security_warning(port);
}
