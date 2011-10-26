#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18330);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");
 
 name["english"] = "Fedora Core 2 2005-277: telnet";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-277 (telnet).

Telnet is a popular protocol for logging into remote systems over the
Internet. The telnet package provides a command line telnet client.

Update Information:

Two buffer overflow flaws were discovered in the way the telnet client
handles messages from a server. An attacker may be able to execute
arbitrary code on a victim's machine if the victim can be tricked into
connecting to a malicious telnet server. The Common Vulnerabilities
and
Exposures project (cve.mitre.org) has assigned the names CVE-2005-0468
and CVE-2005-0469 to these issues.

Red Hat would like to thank iDEFENSE for their responsible disclosure
of
this issue.


Solution : http://www.fedoranews.org/blog/index.php?p=548
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the telnet package";
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
if ( rpm_check( reference:"telnet-0.17-28.FC2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-server-0.17-28.FC2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"telnet-debuginfo-0.17-28.FC2.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"telnet-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}
