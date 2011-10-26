#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:196
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20124);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1849", "CVE-2005-2096");
 
 name["english"] = "MDKSA-2005:196: perl-Compress-Zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:196 (perl-Compress-Zlib).



The perl Compress::Zlib module contains an internal copy of the zlib library
that was vulnerable to CVE-2005-1849 and CVE-2005-2096. This library was
updated with version 1.35 of Compress::Zlib. An updated perl-Compress-Zlib
package is now available to provide the fixed module.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:196
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl-Compress-Zlib package";
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
if ( rpm_check( reference:"perl-Compress-Zlib-1.37-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Compress-Zlib-1.37-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"perl-Compress-Zlib-", release:"MDK10.1")
 || rpm_exists(rpm:"perl-Compress-Zlib-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1849", value:TRUE);
 set_kb_item(name:"CVE-2005-2096", value:TRUE);
}
