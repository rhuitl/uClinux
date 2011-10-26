#
# (C) Tenable Network Security
# Modified by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref 1:
#  Date: Wed, 18 Jun 2003 21:58:51 +0200 (CEST)
#  Subject: Multiple buffer overflows and XSS in Kerio MailServer
#  From: "David F.Madrid" <conde0@telefonica.net>
#  To: <bugtraq@securityfocus.com>
# Ref 2:
#  Abraham Lincoln" <sunninja@scientist.com>
#
#
# This script is released under the GNU GPL v2

if(description)
{
 script_id(11763);
 script_bugtraq_id(5507, 7966, 7967, 7968, 8230, 9975);
 script_cve_id("CVE-2002-1434", "CVE-2003-0487","CVE-2003-0488");
 script_version ("$Revision: 1.9 $");

 name["english"] = "Kerio WebMail v5 multiple flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running version 5 of the Kerio MailServer.

There are multiple flaws in this interface which may allow
an attacker with a valid webmail account on this host 
to obtain a shell on this host or to perform
a cross-site-scripting attack against this host
with version prior to 5.6.4.

Version of MailServer prior to 5.6.5 are also prone to a 
enial of service condition when an incorrect login to the
admin console occurs. This could cause the server to crash.

Version of MailServer prior to 5.7.7 is prone to a remotely 
exploitable buffer overrun condition.
This vulnerability exists in the spam filter component. 
If successfully exploited, this could permit remote attackers 
to execute arbitrary code in the context of the MailServer software. 
This could also cause a denial of service in the server.


*** This might be a false positive, as Nessus did not have
*** the proper credentials to determine if the remote Kerio
*** is affected by this flaw.

Solution : Upgrade to Kerio MailServer 5.7.7 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Kerio MailServer";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security & Copyright (C) 2004 David Maciejak");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);

res = http_get_cache(item:"/", port:port);
if (egrep(string:res, pattern:"^Server: Kerio MailServer ([0-4]\.|5\.[0-6]\.|5\.7\.[0-6])") )	
 		security_warning(port);



