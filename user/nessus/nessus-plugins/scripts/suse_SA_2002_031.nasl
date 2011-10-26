#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:031
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13753);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 script_bugtraq_id(5356);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0391");
 
 name["english"] = "SUSE-SA:2002:031: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:031 (glibc).


An integer overflow has been discovered in the xdr_array() function,
contained in the Sun Microsystems RPC/XDR library, which is part of
the glibc library package on all SUSE products. This overflow allows
a remote attacker to overflow a buffer, leading to remote execution of
arbitrary code supplied by the attacker.

There is no temporary workaround for this security problem other than
disabling all RPC based server and client programs. The permanent
solution is to update the glibc packages with the update packages
listed below.



Solution : http://www.suse.de/security/2002_031_glibc.html
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
if ( rpm_check( reference:"glibc-2.2.2-64", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.2-64", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.2-64", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.4-75", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-75", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-75", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.2.5-123", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.5-123", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.5-123", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"glibc-", release:"SUSE7.2")
 || rpm_exists(rpm:"glibc-", release:"SUSE7.3")
 || rpm_exists(rpm:"glibc-", release:"SUSE8.0") )
{
 set_kb_item(name:"CVE-2002-0391", value:TRUE);
}
