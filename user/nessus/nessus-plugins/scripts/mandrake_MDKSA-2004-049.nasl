#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:049
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14148);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0398");
 
 name["english"] = "MDKSA-2004:049: libneon";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:049 (libneon).


It was discovered that in portions of neon, sscanf() is used in an unsafe
manner. This will result in an overflow of a static heap variable.
The updated packages provide a patched libneon to correct these problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:049
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libneon package";
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
if ( rpm_check( reference:"libneon0.24-0.24.5-0.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libneon0.24-devel-0.24.5-0.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libneon0.24-0.24.5-0.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libneon0.24-devel-0.24.5-0.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libneon-", release:"MDK10.0")
 || rpm_exists(rpm:"libneon-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0398", value:TRUE);
}
