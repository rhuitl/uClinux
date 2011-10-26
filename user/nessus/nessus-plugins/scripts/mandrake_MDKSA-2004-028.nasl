#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:028
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14127);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0180");
 
 name["english"] = "MDKSA-2004:028: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:028 (cvs).


Sebastian Krahmer from the SUSE security team discovered a remotely exploitable
vulnerability in the CVS client. When doing a cvs checkout or update over a
network, the client accepts absolute pathnames in the RCS diff files. A
maliciously configured server could then create any file with content on the
local user's disk. This problem affects all versions of CVS prior to 1.11.15
which has fixed the problem.
The updated packages provide 1.11.14 with the pertinent fix for the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:028
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.14-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.14-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.14-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK10.0")
 || rpm_exists(rpm:"cvs-", release:"MDK9.1")
 || rpm_exists(rpm:"cvs-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0180", value:TRUE);
}
