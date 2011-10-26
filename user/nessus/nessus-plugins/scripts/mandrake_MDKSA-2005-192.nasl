#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:192
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20434);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3178");
 
 name["english"] = "MDKSA-2005:192: xli";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:192 (xli).



Ariel Berkman discovered several buffer overflows in xloadimage, which are also
present in xli, a command line utility for viewing images in X11, and could be
exploited via large image titles and cause the execution of arbitrary code.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:192
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xli package";
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
if ( rpm_check( reference:"xli-1.17.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xli-1.17.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xli-", release:"MDK10.2")
 || rpm_exists(rpm:"xli-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3178", value:TRUE);
}
