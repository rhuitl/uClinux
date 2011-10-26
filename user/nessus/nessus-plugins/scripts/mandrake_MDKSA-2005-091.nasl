#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:091
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18307);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0953", "CVE-2005-1260");
 
 name["english"] = "MDKSA-2005:091: bzip2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:091 (bzip2).



A race condition in the file permission restore code of bunzip2 was discovered
by Imran Ghory. While a user was decompressing a file, a local attacker with
write permissions to the directory containing the compressed file could replace
the target file with a hard link which would cause bunzip2 to restore the file
permissions of the original file to the hard link target. This could be
exploited to gain read or write access to files of other users (CVE-2005-0953).

A vulnerability was found where specially crafted bzip2 archives would cause an
infinite loop in the decompressor, resulting in an indefinitively large output
file (also known as a 'decompression bomb'). This could be exploited to cause a
Denial of Service attack on the host computer due to disk space exhaustion
(CVE-2005-1260).

The provided packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:091
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bzip2 package";
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
if ( rpm_check( reference:"bzip2-1.0.2-17.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.2-17.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.2-17.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.2-20.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.2-20.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.2-20.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.2-20.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.2-20.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.2-20.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"bzip2-", release:"MDK10.0")
 || rpm_exists(rpm:"bzip2-", release:"MDK10.1")
 || rpm_exists(rpm:"bzip2-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0953", value:TRUE);
 set_kb_item(name:"CVE-2005-1260", value:TRUE);
}
