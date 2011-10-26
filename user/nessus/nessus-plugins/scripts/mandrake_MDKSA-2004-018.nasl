#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:018
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14118);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0110");
 
 name["english"] = "MDKSA-2004:018: libxml2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:018 (libxml2).


A flaw in libxml2 versions prior to 2.6.6 was found by Yuuichi Teranishi. When
fetching a remote source via FTP or HTTP, libxml2 uses special parsing routines
that can overflow a buffer if passed a very long URL. In the event that the
attacker can find a program that uses libxml2 which parses remote resources and
allows them to influence the URL, this flaw could be used to execute arbitrary
code.
The updated packages provide a backported fix to correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:018
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libxml2 package";
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
if ( rpm_check( reference:"libxml2-2.5.4-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.5.4-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.5.4-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-utils-2.5.4-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-2.5.11-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.5.11-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.5.11-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-utils-2.5.11-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libxml2-", release:"MDK9.1")
 || rpm_exists(rpm:"libxml2-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0110", value:TRUE);
}
