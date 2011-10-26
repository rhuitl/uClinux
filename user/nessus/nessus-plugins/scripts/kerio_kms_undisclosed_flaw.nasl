#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15404);
 script_cve_id("CVE-2004-2441");
 script_bugtraq_id(11300);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Kerio MailServer < 6.0.3";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Kerio MailServer prior to 6.0.3.

There is an undisclosed flaw in the remote version of this server which might
allow an attacker to execute arbitrary code on the remote host.

Solution : Upgrade to Kerio MailServer 6.0.3 or newer.
See also : http://www.kerio.com/kms_history.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Kerio MailServer < 6.0.3";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_require_ports("Services/smtp", 25);
 exit(0);
}

include("smtp_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("Services/smtp");
if(!port) port = 25;
banner = get_smtp_banner(port:port);
if ( ! banner) exit(0);
if (egrep(string:banner, pattern:"^220 .* Kerio MailServer ([0-5]\.[0-9]\.[0-9]|6\.0\.[0-2]) ESMTP ready") )
	{
		security_hole(port);
		exit(0);
	}
