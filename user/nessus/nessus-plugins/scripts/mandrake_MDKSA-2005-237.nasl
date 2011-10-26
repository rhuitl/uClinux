#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:237
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20468);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4268");
 
 name["english"] = "MDKSA-2005:237: cpio";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:237 (cpio).



A buffer overflow in cpio 2.6 on 64-bit platforms could allow a local user to
create a DoS (crash) and possibly execute arbitrary code when creating a cpio
archive with a file whose size is represented by more than 8 digits. The
updated packages have been patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:237
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cpio package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cpio-2.6-3.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cpio-2.6-5.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cpio-", release:"MDK10.2")
 || rpm_exists(rpm:"cpio-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4268", value:TRUE);
}
