#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:109
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18597);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1921");
 
 name["english"] = "MDKSA-2005:109: php-pear";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:109 (php-pear).



A vulnerability was discovered by GulfTech Security in the PHP XML RPC project.
This vulnerability is considered critical and can lead to remote code
execution. The vulnerability also exists in the PEAR XMLRPC implementation.

Mandriva ships with the PEAR XMLRPC implementation and it has been patched to
correct this problem. It is advised that users examine the PHP applications
they have installed on their servers for any applications that may come bundled
with their own copies of the PEAR system and either patch RPC.php or use the
system PEAR (found in /usr/share/pear).

Updates have been released for some popular PHP applications such as WordPress
and Serendipity and users are urged to take all precautions to protect their
systems from attack and/or defacement by upgrading their applications from the
authors of the respective applications.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:109
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php-pear package";
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
if ( rpm_check( reference:"php-pear-4.3.4-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.8-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.10-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-pear-", release:"MDK10.0")
 || rpm_exists(rpm:"php-pear-", release:"MDK10.1")
 || rpm_exists(rpm:"php-pear-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1921", value:TRUE);
}
