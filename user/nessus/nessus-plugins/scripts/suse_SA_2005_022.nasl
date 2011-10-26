#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18014);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0237", "CVE-2005-0396");
 
 name["english"] = "SUSE-SA:2005:022: kdelibs3";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:022 (kdelibs3).


Several vulnerabilities have been identified and fixed in the KDE
desktop environment.

- A buffer overflow via specially crafted PCX pictures was fixed.

This could lead to a remote attacker being able to execute code
as the user opening or viewing a PCX images. This PCX image could
have been embedded within a web page or Email.

This affects SUSE Linux 9.1 up to 9.3, SUSE Linux Enterprise Server
9 and Novell Linux Desktop 9.


- The IDN domain name cloaking problem was fixed.

A remote website could disguise its name as another potentially
trusted site by using a extension originally meant for non-ASCII
domain names by using 'homographs' which look exactly like other
letters.

The fix used by KDE is only use homographs for trusted domains.
It is disabled by default for the .net, .com and .org domains.

This issue exists in SUSE Linux 9.1 and 9.2, SUSE Linux Enterprise
Server 9 and Novell Linux Desktop 9.  It has been assigned the
Mitre CVE ID  CVE-2005-0233.


- A denial of service attack against the DCOP service was fixed.

A local user could cause another users KDE session to visible hang
by writing bad data to the world writable DCOP socket. The socket
has been made writable only for the user itself.

This was found by Sebastian Krahmer of SUSE Security.

This affects all SUSE Linux versions, except SUSE Linux 9.3.
Updates for SUSE Linux up to 9.0 and SUSE Linux Enterprise Server
8 are not included for this minor issue. They will be included
should a later security update for different issues be necessary.

This is tracked by the Mitre CVE ID CVE-2005-0396.

Additionally following bug was fixed:

- A possible race in the DNS resolver causing unresolved hosts in rare
cases was fixed.  This only affected SUSE Linux 9.3.


Solution : http://www.suse.de/security/advisories/2005_22_kdelibs3.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs3 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdelibs3-3.2.1-44.46", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.3.0-34.5", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.4.0-20.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs3-", release:"SUSE9.1")
 || rpm_exists(rpm:"kdelibs3-", release:"SUSE9.2")
 || rpm_exists(rpm:"kdelibs3-", release:"SUSE9.3") )
{
 set_kb_item(name:"CVE-2005-0237", value:TRUE);
 set_kb_item(name:"CVE-2005-0396", value:TRUE);
}
