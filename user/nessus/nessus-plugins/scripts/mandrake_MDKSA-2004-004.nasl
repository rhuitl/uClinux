#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:004
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14104);
 script_bugtraq_id(8780);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0848");
 
 name["english"] = "MDKSA-2004:004: slocate";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:004 (slocate).


A vulnerability was discovered by Patrik Hornik in slocate versions up to and
including 2.7 where a carefully crafted database could overflow a heap-based
buffer. This could be exploited by a local user to gain privileges of the
'slocate' group. The updated packages contain a patch from Kevin Lindsay that
causes slocate to drop privileges before reading a user-supplied database.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:004
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
if ( rpm_check( reference:"slocate-2.7-2.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"slocate-2.7-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"slocate-", release:"MDK9.1")
 || rpm_exists(rpm:"slocate-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0848", value:TRUE);
}
