#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:156
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20424);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2496");
 
 name["english"] = "MDKSA-2005:156: ntp";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:156 (ntp).



When starting xntpd with the -u option and specifying the group by using a
string not a numeric gid the daemon uses the gid of the user not the group.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:156
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ntp package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ntp-4.2.0-18.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ntp-client-4.2.0-18.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ntp-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2496", value:TRUE);
}
