#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:045
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13948);
 script_bugtraq_id(5352);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0658");
 
 name["english"] = "MDKSA-2002:045: mm";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:045 (mm).


Marcus Meissner and Sebastian Krahmer discovered a temporary file vulnerability
in the mm library which is used by the Apache webserver. This vulnerability can
be exploited to obtain root privilege if shell access to the apache user
(typically apache or nobody) is already obtained.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:045
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mm package";
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
if ( rpm_check( reference:"mm-1.1.3-8.5mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mm-devel-1.1.3-8.5mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mm-1.1.3-8.5mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mm-devel-1.1.3-8.5mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mm-1.1.3-8.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mm-devel-1.1.3-8.4mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmm1-1.1.3-9.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmm1-devel-1.1.3-9.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmm1-1.1.3-9.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libmm1-devel-1.1.3-9.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mm-", release:"MDK7.1")
 || rpm_exists(rpm:"mm-", release:"MDK7.2")
 || rpm_exists(rpm:"mm-", release:"MDK8.0")
 || rpm_exists(rpm:"mm-", release:"MDK8.1")
 || rpm_exists(rpm:"mm-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0658", value:TRUE);
}
