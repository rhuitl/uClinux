#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:027
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13796);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0007");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0028");
 
 name["english"] = "SUSE-SA:2003:027: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:027 (glibc).


Another integer overflow was found in glibc' XDR code. This bug is equal

Solution : http://www.suse.de/security/2003_027_glibc.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the glibc package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"glibc-2.2-26", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.2-68", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.4-78", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.5-177", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"glibc-", release:"SUSE7.1")
 || rpm_exists(rpm:"glibc-", release:"SUSE7.2")
 || rpm_exists(rpm:"glibc-", release:"SUSE7.3")
 || rpm_exists(rpm:"glibc-", release:"SUSE8.0") )
{
 set_kb_item(name:"CVE-2003-0028", value:TRUE);
}
