#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:059
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13960);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2001-1246");
 
 name["english"] = "MDKSA-2002:059: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:059 (php).


A fifth parameter was added to PHP's mail() function in 4.0.5 that is not
properly sanitized when the server is running in safe mode. This vulnerability
would allow local users and, possibly, remote attackers to execute arbitrary
commands using shell metacharacters.
After upgrading to these packages, execute 'service httpd restart' as root in
order to close the hole immediately.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:059
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
if ( rpm_check( reference:"php-4.0.6-6.4mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-common-4.0.6-6.4mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.0.6-6.4mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-4.0.6-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-common-4.0.6-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.0.6-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-4.0.6-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-common-4.0.6-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.0.6-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-4.0.6-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-common-4.0.6-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.0.6-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK7.1")
 || rpm_exists(rpm:"php-", release:"MDK7.2")
 || rpm_exists(rpm:"php-", release:"MDK8.0")
 || rpm_exists(rpm:"php-", release:"MDK8.1") )
{
 set_kb_item(name:"CVE-2001-1246", value:TRUE);
}
