#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:0015
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13779);
 script_bugtraq_id(6974);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0108");
 
 name["english"] = "SUSE-SA:2003:0015: tcpdump";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:0015 (tcpdump).


The network traffic analyzer tool tcpdump is vulnerable to a denial-of-
service condition while parsing ISAKMP or BGP packets. This bug can
be exploited remotely by an attacker to stop the use of tcpdump for
analyzing network traffic for signs of security breaches or alike.
Another bug may lead to system compromise due to the handling of
malformed NFS packets send by an attacker.
Please note, that tcpdump drops root privileges right after allocating
the needed raw sockets.

There is no temporary fix known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_015_tcpdump.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcpdump package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"tcpdump-3.4a6-375", release:"SUSE7.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.4a6-376", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-321", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.6.2-322", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"tcpdump-3.7.1-198", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"tcpdump-", release:"SUSE7.1")
 || rpm_exists(rpm:"tcpdump-", release:"SUSE7.2")
 || rpm_exists(rpm:"tcpdump-", release:"SUSE7.3")
 || rpm_exists(rpm:"tcpdump-", release:"SUSE8.0")
 || rpm_exists(rpm:"tcpdump-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2003-0108", value:TRUE);
}
