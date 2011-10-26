#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:141
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19898);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2549", "CVE-2005-2550");
 
 name["english"] = "MDKSA-2005:141: evolution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:141 (evolution).



Multiple format string vulnerabilities in Evolution 1.5 through 2.3.6.1 allow
remote attackers to cause a denial of service (crash) and possibly execute
arbitrary code via (1) full vCard data, (2) contact data from remote LDAP
servers, or (3) task list data from remote servers. (CVE-2005-2549)

A format string vulnerability in Evolution 1.4 through 2.3.6.1 allows remote
attackers to cause a denial of service (crash) and possibly execute arbitrary
code via the calendar entries such as task lists, which are not properly
handled when the user selects the Calendars tab. (CVE-2005-2550)



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:141
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the evolution package";
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
if ( rpm_check( reference:"evolution-2.0.3-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.3-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.0.3-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-2.0.4-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.4-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-pilot-2.0.4-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"evolution-", release:"MDK10.1")
 || rpm_exists(rpm:"evolution-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2549", value:TRUE);
 set_kb_item(name:"CVE-2005-2550", value:TRUE);
}
