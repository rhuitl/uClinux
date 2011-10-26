#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20351);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4348");
 
 name["english"] = "Fedora Core 4 2005-1187: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1187 (fetchmail).

Fetchmail is a remote mail retrieval and forwarding utility intended
for use over on-demand TCP/IP links, like SLIP or PPP connections.
Fetchmail supports every remote-mail protocol currently in use on the
Internet (POP2, POP3, RPOP, APOP, KPOP, all IMAPs, ESMTP ETRN, IPv6,
and IPSEC) for retrieval. Then Fetchmail forwards the mail through
SMTP so you can read it through your favorite mail client.

Install fetchmail if you need to retrieve mail over SLIP or PPP
connections.

Update Information:

Fetchmail contains a bug where when running in multidrop
mode, a
malicious mail server can crash the client by sending a message
without headers.

This update fixes the issue.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fetchmail package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"fetchmail-6.2.5.5-1.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"fetchmail-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-4348", value:TRUE);
}
