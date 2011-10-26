#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13785);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0411");
 
 name["english"] = "SuSE-SA:2003:014: kdelibs/kdelibs3";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2003:014 (kdelibs/kdelibs3).


The kdelibs3 (kdelibs for SLES7 based products) package is a core package
for the K desktop environment (KDE). The URI handler of the kdelibs3
and kdelibs class library contains a flaw which allows remote
attackers to create arbitrary files as the user utilizing the
kdelibs3/kdelibs package.
Affected are applications which use the kdelibs3/kdelibs URI handler
such as Konqueror or Kmail.
The original KDE advisory can be found at
http://www.kde.org/info/security/advisory-20040517-1.html


Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_14_kdelibs.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs/kdelibs3 package";
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
if ( rpm_check( reference:"kdelibs3-3.0-120", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.0.5-54", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.1.1-139", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.1.4-51", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.2.1-44.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"SUSE8.0")
 || rpm_exists(rpm:"kdelibs-", release:"SUSE8.1")
 || rpm_exists(rpm:"kdelibs-", release:"SUSE8.2")
 || rpm_exists(rpm:"kdelibs-", release:"SUSE9.0")
 || rpm_exists(rpm:"kdelibs-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0411", value:TRUE);
}
