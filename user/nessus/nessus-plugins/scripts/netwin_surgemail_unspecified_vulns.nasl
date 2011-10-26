#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17594);
 script_version ("$Revision: 1.1 $");
 script_bugtraq_id(12866);
 
 name["english"] = "NetWin SurgeMail Multiple Remote Unspecified Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running NetWin SurgeMail, a mail server application.

The remote version of this software is vulnerable to multiple unspecified
vulnerabilities which have been disclosed by the vendor.

Solution : Upgrade to NetWin SurgeMail 3.0.0c2 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks the version of the remote NetWin server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);

if ( ! banner ) exit(0);

if ( egrep(string:banner, pattern:"^220.* SurgeSMTP \(Version ([0-2]\.|3\.0[ab]|3\.0c[01][^0-9])")) security_warning(port);
