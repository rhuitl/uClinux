#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:015
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14000);
 script_bugtraq_id(6676);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0056");
 
 name["english"] = "MDKSA-2003:015: slocate";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:015 (slocate).


A buffer overflow vulnerability was discovered in slocate by team USG. The
overflow appears when slocate is used with the -c and -r parameters, using a
1024 (or 10240) byte string. This has been corrected in slocate version 2.7.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:015
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the slocate package";
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
if ( rpm_check( reference:"slocate-2.7-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"slocate-2.7-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"slocate-2.7-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"slocate-2.7-1.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"slocate-", release:"MDK8.0")
 || rpm_exists(rpm:"slocate-", release:"MDK8.1")
 || rpm_exists(rpm:"slocate-", release:"MDK8.2")
 || rpm_exists(rpm:"slocate-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0056", value:TRUE);
}
