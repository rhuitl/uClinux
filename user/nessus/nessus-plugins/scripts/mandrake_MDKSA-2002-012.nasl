#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:012
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13920);
 script_bugtraq_id(3869);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0003");
 
 name["english"] = "MDKSA-2002:012: groff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:012 (groff).


zen-parse discovered an exploitable buffer overflow in groff's preprocessor. If
groff is invoked using the LPRng printing system, an attacker can gain rights as
the 'lp' user. Likewise, this may be remotely exploitable if lpd is running and
remotely accessible and the attacker knows the name of the printer and it's
spool file.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:012
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the groff package";
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
if ( rpm_check( reference:"groff-1.16.1-7.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-for-man-1.16.1-7.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-gxditview-1.16.1-7.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-perl-1.16.1-7.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-1.16.1-7.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-for-man-1.16.1-7.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-gxditview-1.16.1-7.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-perl-1.16.1-7.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-1.17.2-3.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-for-man-1.17.2-3.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-gxditview-1.17.2-3.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"groff-perl-1.17.2-3.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"groff-", release:"MDK7.2")
 || rpm_exists(rpm:"groff-", release:"MDK8.0")
 || rpm_exists(rpm:"groff-", release:"MDK8.1") )
{
 set_kb_item(name:"CVE-2002-0003", value:TRUE);
}
