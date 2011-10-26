#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:044
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13765);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-a-0006");
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1219", "CVE-2002-1221");
 
 name["english"] = "SUSE-SA:2002:044: bind8";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:044 (bind8).


The security research company ISS (Internet Security Services)
has discovered several vulnerabilities in the BIND8 name server,
including a remotely exploitable buffer overflow.


1.	There is a buffer overflow in the way named handles
SIG records. This buffer overflow can be exploited to
obtain access to the victim host under the account
the named process is running with.

2.	There are several Denial Of Service problems in BIND8
that allow remote attackers to terminate the name server
process.

Both vulnerabilities are addressed by this update, using patches
originating from ISC.


Solution : http://www.suse.de/security/2002_004_bind8.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bind8 package";
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
if ( rpm_check( reference:"bind8-8.2.3-200", release:"SUSE7.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.3-200", release:"SUSE7.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.3-200", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.3-200", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.3-200", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.3-200", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-devel-8.2.3-200", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.4-261", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.4-261", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-devel-8.2.4-261", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.4-260", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.4-260", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-devel-8.2.4-260", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-8.2.4-260", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bindutil-8.2.4-260", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind8-devel-8.2.4-260", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"bind8-", release:"SUSE7.0")
 || rpm_exists(rpm:"bind8-", release:"SUSE7.1")
 || rpm_exists(rpm:"bind8-", release:"SUSE7.2")
 || rpm_exists(rpm:"bind8-", release:"SUSE7.3")
 || rpm_exists(rpm:"bind8-", release:"SUSE8.0")
 || rpm_exists(rpm:"bind8-", release:"SUSE8.1") )
{
 set_kb_item(name:"CVE-2002-1219", value:TRUE);
 set_kb_item(name:"CVE-2002-1221", value:TRUE);
}
