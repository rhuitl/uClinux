#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13683);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0008");
 script_bugtraq_id(9423);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0989", "CVE-2004-0055", "CVE-2004-0057");
 
 name["english"] = "Fedora Core 1 2004-092: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-092 (tcpdump).

Tcpdump is a command-line tool for monitoring network traffic.
Tcpdump can capture and display the packet headers on a particular
network interface or on all interfaces.  Tcpdump can display all of
the packet headers, or just the ones that match particular criteria.

Install tcpdump if you need a program to monitor network traffic.

Update Information:

Updated tcpdump, libpcap, and arpwatch packages fix vulnerabilities in
ISAKMP and RADIUS parsing.

Tcpdump is a command-line tool for monitoring network traffic.

George Bakos discovered flaws in the ISAKMP decoding routines of tcpdump
versions prior to 3.8.1. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2003-0989 to this issue.

Jonathan Heusser discovered an additional flaw in the ISAKMP decoding
routines for tcpdump 3.8.1 and earlier. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0057 to
this issue.

Jonathan Heusser discovered a flaw in the print_attr_string function in
the RADIUS decoding routines for tcpdump 3.8.1 and earlier. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0055 to this issue.

Remote attackers could potentially exploit these issues by sending
carefully-crafted packets to a victim. If the victim uses tcpdump, these
pakets could result in a denial of service, or possibly execute
arbitrary code as the 'pcap' user.

Users of tcpdump are advised to upgrade to these erratum packages, which
contain backported security patches and are not vulnerable to these issues.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-092.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcpdump package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"tcpdump-3.7.2-8.fc1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpcap-0.7.2-8.fc1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"arpwatch-2.1a11-8.fc1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-debuginfo-3.7.2-8.fc1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"tcpdump-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0989", value:TRUE);
 set_kb_item(name:"CVE-2004-0055", value:TRUE);
 set_kb_item(name:"CVE-2004-0057", value:TRUE);
}
