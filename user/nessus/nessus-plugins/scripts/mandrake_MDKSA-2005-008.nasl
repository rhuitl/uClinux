#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:008
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16184);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270");
 
 name["english"] = "MDKSA-2005:008: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:008 (cups).



A buffer overflow was discovered in the ParseCommand function in the hpgltops
utility. An attacker with the ability to send malicious HPGL files to a printer
could possibly execute arbitrary code as the 'lp' user (CVE-2004-1267).

Vulnerabilities in the lppasswd utility were also discovered. The program
ignores write errors when modifying the CUPS passwd file. A local user who is
able to fill the associated file system could corrupt the CUPS passwd file or
prevent future use of lppasswd (CVE-2004-1268 and CVE-2004-1269). As well,
lppasswd does not verify that the passwd.new file is different from STDERR,
which could allow a local user to control output to passwd.new via certain user
input that could trigger an error message (CVE-2004-1270).

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:008
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.20-5.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.20-5.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.20-5.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.1.20-5.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.1.20-5.5.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.21-0.rc1.7.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.21-0.rc1.7.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.21-0.rc1.7.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.1.21-0.rc1.7.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.1.21-0.rc1.7.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.19-10.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.1.19-10.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.1.19-10.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.1.19-10.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.1.19-10.5.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK10.0")
 || rpm_exists(rpm:"cups-", release:"MDK10.1")
 || rpm_exists(rpm:"cups-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-1267", value:TRUE);
 set_kb_item(name:"CVE-2004-1268", value:TRUE);
 set_kb_item(name:"CVE-2004-1269", value:TRUE);
 set_kb_item(name:"CVE-2004-1270", value:TRUE);
}
