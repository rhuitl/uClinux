#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:015
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13831);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418");
 
 name["english"] = "SuSE-SA:2004:015: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:015 (cvs).


The Concurrent Versions System (CVS) offers tools which allow developers
to share and maintain large software projects.
Various remotely exploitable conditions have been found during a
source code review of CVS done by Stefan Esser and Sebastian Krahmer
(SuSE Security-Team).
These bugs allow remote attackers to execute arbitrary code as the user
the CVS server runs as. Since there is no easy workaround we strongly
recommend to update the cvs package.
The update packages fix vulnerabilities which have been assigned the
CAN numbers CVE-2004-0416, CVE-2004-0417 and CVE-2004-0418.
The cvs packages shipped by SUSE (as well as our recent updates for CVS)
are not vulnerable to CVE-2004-0414.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2004_15_cvs.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.1p1-332", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.1p1-332", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.5-114", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.6-83", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.14-24.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"SUSE8.0")
 || rpm_exists(rpm:"cvs-", release:"SUSE8.1")
 || rpm_exists(rpm:"cvs-", release:"SUSE8.2")
 || rpm_exists(rpm:"cvs-", release:"SUSE9.0")
 || rpm_exists(rpm:"cvs-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0416", value:TRUE);
 set_kb_item(name:"CVE-2004-0417", value:TRUE);
 set_kb_item(name:"CVE-2004-0418", value:TRUE);
}
