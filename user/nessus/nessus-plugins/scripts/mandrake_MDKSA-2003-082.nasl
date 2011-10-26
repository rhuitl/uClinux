#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:082
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14064);
 script_bugtraq_id(5562, 5681, 7761);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2002-0985", "CVE-2002-0986", "CVE-2003-0442");
 
 name["english"] = "MDKSA-2003:082: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:082 (php).


A vulnerability was discovered in the transparent session ID support in PHP4
prior to version 4.3.2. It did not properly escape user- supplied input prior to
inserting it in the generated web page. This could be exploited by an attacker
to execute embedded scripts within the context of the generated HTML
(CVE-2003-0442).
As well, two vulnerabilities had not been patched in the PHP packages included
with Mandrake Linux 8.2: The mail() function did not filter ASCII control
filters from its arguments, which could allow an attacker to modify the mail
message content (CVE-2002-0986). Another vulnerability in the mail() function
would allow a remote attacker to bypass safe mode restrictions and modify the
command line arguments passed to the MTA in the fifth argument (CVE-2002-0985).
All users are encouraged to upgrade to these patched packages.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:082
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php package";
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
if ( rpm_check( reference:"php-4.1.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-common-4.1.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.1.2-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-4.2.3-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-common-4.2.3-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.2.3-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.2.3-4.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libphp_common430-430-11.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cgi-4.3.1-11.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-cli-4.3.1-11.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php430-devel-430-11.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK8.2")
 || rpm_exists(rpm:"php-", release:"MDK9.0")
 || rpm_exists(rpm:"php-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2002-0985", value:TRUE);
 set_kb_item(name:"CVE-2002-0986", value:TRUE);
 set_kb_item(name:"CVE-2003-0442", value:TRUE);
}
