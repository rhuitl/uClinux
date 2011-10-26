#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:031
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14730);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(11183, 11184);
 script_cve_id("CVE-2004-0558", "CVE-2004-0801");
 
 name["english"] = "SUSE-SA:2004:031: cups";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:031 (cups).


The Common Unix Printing System (CUPS) enables local and remote users to
obtain printing functionallity via the Internet Printing Protocol (IPP).
Alvaro Martinez Echevarria has found a remote Denial of Service condition
within CUPS which allows remote users to make the cups server unresponsive.
Additionally the SUSE Security Team has discovered a flaw in the
foomatic-rip print filter which is commonly installed along with cups.
It allows remote attackers, which are listed in the printing ACLs, to
execute arbitrary commands as the printing user 'lp'.



Solution : http://www.suse.de/security/2004_31_cups.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cups package";
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
if ( rpm_check( reference:"cups-1.1.15-170", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.15-170", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.15-170", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.18-96", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.18-96", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.18-96", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.19-93", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.19-93", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.19-93", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-filters-3.0.0-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.20-108.8", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.20-108.8", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-client-1.1.20-108.8", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-filters-3.0.1-41.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"SUSE8.1")
 || rpm_exists(rpm:"cups-", release:"SUSE8.2")
 || rpm_exists(rpm:"cups-", release:"SUSE9.0")
 || rpm_exists(rpm:"cups-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0558", value:TRUE);
 set_kb_item(name:"CVE-2004-0801", value:TRUE);
}
