#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:085
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18274);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1046");
 
 name["english"] = "MDKSA-2005:085: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:085 (kdelibs).



A buffer overflow in the PCX decoder of kimgio was discovered by Bruno Rohee.
If an attacker could trick a user into loading a malicious PCX image with any
KDE application, he could cause the execution of arbitrary code with the
privileges of the user opening the image.

The provided packages have been patched to correct this issue.

In addition, the LE2005 packages contain fixes to configuring email into
kbugreport, fixing a KDE crasher bug, fixing a kicondialog bug, a KHTML bug,
and a knewsticker export symbol problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:085
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"kdelibs-common-3.2.3-106.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2.3-106.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2.3-106.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.3.2-124.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.3.2-124.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.3.2-124.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK10.1")
 || rpm_exists(rpm:"kdelibs-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1046", value:TRUE);
}
