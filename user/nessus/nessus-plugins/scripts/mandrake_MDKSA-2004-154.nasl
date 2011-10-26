#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:154
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16035);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1145");
 
 name["english"] = "MDKSA-2004:154: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:154 (kdelibs).



A vulnerability in the Konqueror webbrowser was discovered where an untrusted
java applet could escalate privileges (through JavaScript calling into Java
code). This includes the reading and writing of files with the privileges of
the user running the applet.

The provided packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:154
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"kdelibs-common-3.2-36.7.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2-36.7.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2-36.7.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.2.3-99.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2.3-99.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2.3-99.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK10.0")
 || rpm_exists(rpm:"kdelibs-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1145", value:TRUE);
}
