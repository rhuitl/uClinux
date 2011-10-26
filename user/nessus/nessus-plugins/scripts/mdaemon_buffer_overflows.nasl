#
# (C) Tenable Network Security
# 

if(description)
{
 script_id(14804);
 script_cve_id("CVE-2004-1546");
 script_bugtraq_id(11238);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Alt-N MDaemon Multiple Buffer Overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Alt-N MDaemon, an SMTP/IMAP server for the Windows 
operating system family. 
It is reported that versions up to and including 6.5.1 are prone to multiple 
buffer overflow vulnerabilities. 

An attacker may cause a denial of service execute arbitrary code on the 
remote server. 

The attacker needs to authenticate in order to exploit these vulnerabilities 
against the IMAP server but it doesn't need to do so against the SMTP server.

Solution : Upgrade to MDaemon 6.5.2 or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote version of Mdaemon";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SMTP problems";
 script_family(english:family["english"], francais:family["francais"]);
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

if ( egrep(pattern:"^220.*ESMTP MDaemon ([0-5][^0-9]|6\.([0-4][^0-9]|5\.[0-1]))", string:banner) ) security_hole(port);
