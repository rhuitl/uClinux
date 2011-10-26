#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:069
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14052);
 script_bugtraq_id(7551);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0334");
 
 name["english"] = "MDKSA-2003:069: BitchX";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:069 (BitchX).


A Denial Of Service (DoS) vulnerability was discovered in BitchX that would
allow a remote attacker to crash BitchX by changing certain channel modes. This
vulnerability has been fixed in CVS and patched in the released updates.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:069
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the BitchX package";
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
if ( rpm_check( reference:"BitchX-1.0-0.c19.3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"BitchX-1.0-0.c19.4.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"BitchX-", release:"MDK9.0")
 || rpm_exists(rpm:"BitchX-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0334", value:TRUE);
}
