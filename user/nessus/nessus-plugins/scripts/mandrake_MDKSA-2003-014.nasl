#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:014
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13999);
 script_bugtraq_id(6763);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0018");
 
 name["english"] = "MDKSA-2003:014: kernel";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:014 (kernel).


An updated kernel for 9.0 is available with a number of bug fixes. Supermount
has been completely overhauled and should be solid on all systems. Other fixes
include XFS with high memory, a netfilter fix, a fix for Sony VAIO DMI, i845
should now work with UDMA, and new support for VIA C3 is included. Prism24 has
been updated so it now works properly on HP laptops and a new ACPI is included,
although it is disabled by default for broader compatibility.
This also fixes a security problem that allows non-root users to freeze the
kernel, and a fix for a vulnerability in O_DIRECT handling that can create a
limited information leak where any user on the system with write privilege to
the file system from previously deleted files. This also allows users to create
minor file system corruption (this can easily be repaired by fsck).
For instructions on how to update your kernel, please visit
http://www.mandrakesecure.net/en/kernelupdate.php


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:014
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kernel package";
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
if ( rpm_check( reference:"kernel-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.19-24mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.19-24mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0018", value:TRUE);
}
