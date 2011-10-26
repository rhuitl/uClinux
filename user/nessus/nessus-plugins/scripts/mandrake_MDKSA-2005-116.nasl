#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:116-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18678);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2005-1111", "CVE-2005-1229");
 
 name["english"] = "MDKSA-2005:116-1: cpio";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:116-1 (cpio).



A race condition has been found in cpio 2.6 and earlier which allows local
users to modify permissions of arbitrary files via a hard link attack on a file
while it is being decompressed, whose permissions are changed by cpio after the
decompression is complete (CVE-2005-1111).

A vulnerability has been discovered in cpio that allows a malicious cpio file
to extract to an arbitrary directory of the attackers choice. cpio will extract
to the path specified in the cpio file, this path can be absolute
(CVE-2005-1229).

Update:

The previous packages had a problem upgrading due to an unresolved issue with
tar and rmt. These packages correct the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:116-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cpio package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cpio-2.5-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cpio-2.5-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cpio-2.6-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cpio-", release:"MDK10.0")
 || rpm_exists(rpm:"cpio-", release:"MDK10.1")
 || rpm_exists(rpm:"cpio-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1111", value:TRUE);
 set_kb_item(name:"CVE-2005-1229", value:TRUE);
}
