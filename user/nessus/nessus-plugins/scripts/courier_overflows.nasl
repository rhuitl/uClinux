#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12102);
 script_cve_id("CVE-2004-0224");
 script_bugtraq_id(9845);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "Courier remote overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote mail server is the Courier MTA. 

There is a buffer overflow in the conversions functions of this software
which may allow an attacker to execute arbitrary code on this host.

Solution : Upgrade to Courier 0.45 or newer
Risk factor : High";
	
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version number"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "SMTP problems";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
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
 if ( egrep(pattern:"220.*Courier 0\.([0-9]\.|[0-3][0-9]\.|4[0-4]\.)", string:banner) ) { security_hole(port); exit(0); }

}
