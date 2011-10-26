#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:144
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15917);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0972");
 
 name["english"] = "MDKSA-2004:144: lvm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:144 (lvm).



The Trustix developers discovered that the lvmcreate_initrd script, part of the
lvm1 package, created a temporary directory in an insecure manner. This could
allow for a symlink attack to create or overwrite arbitrary files with the
privileges of the user running the script.

The updated packages have been patched to prevent this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:144
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lvm package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"lvm1-1.0.8-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lvm1-1.0.8-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lvm-1.0.7-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"lvm-", release:"MDK10.0")
 || rpm_exists(rpm:"lvm-", release:"MDK10.1")
 || rpm_exists(rpm:"lvm-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0972", value:TRUE);
}
