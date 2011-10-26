#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:019
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14004);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1396");
 
 name["english"] = "MDKSA-2003:019: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:019 (php).


A buffer overflow was discovered in the wordwrap() function in versions of PHP
greater than 4.1.2 and less than 4.3.0. Under certain circumstances, this buffer
overflow can be used to overwite heap memory and could potentially lead to
remote system compromise.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:019
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
if ( rpm_check( reference:"php-4.2.3-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-common-4.2.3-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.2.3-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.2.3-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1396", value:TRUE);
}
