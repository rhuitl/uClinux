#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19272);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2355");
 
 name["english"] = "Fedora Core 3 2005-614: fetchmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-614 (fetchmail).

Fetchmail is a remote mail retrieval and forwarding utility intended
for use over on-demand TCP/IP links, like SLIP or PPP connections.
Fetchmail supports every remote-mail protocol currently in use on the
Internet (POP2, POP3, RPOP, APOP, KPOP, all IMAPs, ESMTP ETRN, IPv6,
and IPSEC) for retrieval. Then Fetchmail forwards the mail through
SMTP so you can read it through your favorite mail client.

Install fetchmail if you need to retrieve mail over SLIP or PPP
connections.

Update Information:

A buffer overflow was discovered in fetchmail's POP3 client. A
malicious
server could cause fetchmail to execute arbitrary code.

The Common Vulnerabilities and Exposures project has assigned the name
CVE-2005-2355 to this issue.

All fetchmail users should upgrade to the updated package, which fixes
this issue.


Solution : http://www.fedoranews.org/blog/index.php?p=780
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
if ( rpm_check( reference:"fetchmail-6.2.5-7.fc3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"fetchmail-debuginfo-6.2.5-7.fc3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"fetchmail-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2355", value:TRUE);
}
