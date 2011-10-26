#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:136
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20423);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2097");
 
 name["english"] = "MDKSA-2005:136: gpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:136 (gpdf).



A vulnerability in the gpdf PDF viewer was discovered. An attacker could
construct a malicious PDF file that would cause gpdf to consume all available
disk space in /tmp when opened.

The updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:136
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpdf package";
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
if ( rpm_check( reference:"gpdf-2.8.3-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gpdf-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2097", value:TRUE);
}
