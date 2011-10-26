#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15828);
 script_cve_id("CVE-2004-1128", "CVE-2004-1129", "CVE-2004-1130");
 script_bugtraq_id(11742);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Youngzsoft CMailServer Multiple Remote Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running YoungZSoft CMail Server, a mail server for Microsoft
Windows. 

There are multiple remote vulnerabilities like buffer overflow, SQL injection,
HTML injection in the remote version of this software which may allow an 
attacker to execute arbitrary code on the remote host.

Solution : Upgrade to CMailServer 5.2.1 or later
Risk Factor : High";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Detects the version of CMail";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "SMTP problems"; 
 
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/cmailserver-smtp");
 exit(0);
}

#
# The script code starts here
#
include("smtp_func.inc");
port = get_kb_item("Services/cmailserver-smtp");
if ( ! port ) exit(0);
banner = get_smtp_banner ( port:port);
if ( egrep(pattern:"^220 ESMTP CMailServer ([0-4]\.*|5\.([0-1]\..*|2\.0.*))SMTP Service Ready", string:banner) )
	security_hole ( port );

