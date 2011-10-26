#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:010
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14110);
 script_bugtraq_id(9641);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0078");
 
 name["english"] = "MDKSA-2004:010: mutt";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:010 (mutt).


A bug in mutt was reported by Neils Heinen that could allow a remote attacker to
send a carefully crafted mail message that can cause mutt to segfault and
possibly execute arbitrary code as the user running mutt.
The updated packages have been patched to correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:010
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mutt package";
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
if ( rpm_check( reference:"mutt-1.4.1i-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mutt-1.4.1i-3.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"mutt-", release:"MDK9.1")
 || rpm_exists(rpm:"mutt-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0078", value:TRUE);
}
