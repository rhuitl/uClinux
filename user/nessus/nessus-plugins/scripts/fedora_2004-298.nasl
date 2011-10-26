#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14702);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(11075);
 script_cve_id("CVE-2004-0806");
 
 name["english"] = "Fedora Core 2 2004-298: cdrtools";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-298 (cdrtools).

cdrtools is a collection of CD/DVD utilities.

Update Information:

Anyone who has manually suid /usr/bin/cdrecord should update to this version.

http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0806



Solution : http://www.fedoranews.org/updates/FEDORA-2004-298.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cdrtools package";
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
if ( rpm_check( reference:"cdrecord-2.01-0.a27.4.FC2.3", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-2.01-0.a27.4.FC2.3", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-2.01-0.a27.4.FC2.3", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdda2wav-2.01-0.a27.4.FC2.3", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrtools-debuginfo-2.01-0.a27.4.FC2.3", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"cdrtools-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0806", value:TRUE);
}
