#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:042
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14141);
 script_bugtraq_id(10247);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0426");
 
 name["english"] = "MDKSA-2004:042: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:042 (rsync).


Rsync before 2.6.1 does not properly sanitize paths when running a read/write
daemon without using chroot, allows remote attackers to write files outside of
the module's path.
The updated packages provide a patched rsync to correct this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:042
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rsync package";
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
if ( rpm_check( reference:"rsync-2.6.0-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"rsync-", release:"MDK10.0")
 || rpm_exists(rpm:"rsync-", release:"MDK9.1")
 || rpm_exists(rpm:"rsync-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0426", value:TRUE);
}
