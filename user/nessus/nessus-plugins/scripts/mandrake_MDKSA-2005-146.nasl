#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:146
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19902);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2498");
 
 name["english"] = "MDKSA-2005:146: php-pear";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:146 (php-pear).



A problem was discovered in the PEAR XML-RPC Server package included in the
php-pear package. If a PHP script which implements the XML-RPC Server is used,
it would be possible for a remote attacker to construct an XML-RPC request
which would cause PHP to execute arbitrary commands as the 'apache' user.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:146
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
if ( rpm_check( reference:"php-pear-4.3.4-3.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.8-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.10-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-pear-", release:"MDK10.0")
 || rpm_exists(rpm:"php-pear-", release:"MDK10.1")
 || rpm_exists(rpm:"php-pear-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2498", value:TRUE);
}
