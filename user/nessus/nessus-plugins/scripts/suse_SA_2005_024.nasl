#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:024
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18082);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0753");
 
 name["english"] = "SUSE-SA:2005:024: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:024 (cvs).


The Concurrent Versions System (CVS) offers tools which allow developers
to share and maintain large software projects.
The current maintainer of CVS reported various problems within CVS
such as a buffer overflow and memory access problems which have
been fixed within the available updates.
The CVE project has assigned the CAN number CVE-2005-0753.


Solution : http://www.suse.de/security/advisories/2005_24_cvs.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"cvs-1.11.5-116", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.6-85", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.14-24.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.12.9-2.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.12.11-4.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"SUSE8.2")
 || rpm_exists(rpm:"cvs-", release:"SUSE9.0")
 || rpm_exists(rpm:"cvs-", release:"SUSE9.1")
 || rpm_exists(rpm:"cvs-", release:"SUSE9.2")
 || rpm_exists(rpm:"cvs-", release:"SUSE9.3") )
{
 set_kb_item(name:"CVE-2005-0753", value:TRUE);
}
