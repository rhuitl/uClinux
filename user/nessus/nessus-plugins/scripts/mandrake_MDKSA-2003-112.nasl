#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:112-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14094);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(9178);
 script_cve_id("CVE-2003-0977");
 
 name["english"] = "MDKSA-2003:112-1: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:112-1 (cvs).


A vulnerability was discovered in the CVS server < 1.11.10 where a malformed
module request could cause the CVS server to attempt to create directories and
possibly files at the root of the filesystem holding the CVS repository.
Updated packages are available that fix the vulnerability by providing CVS
1.11.10 on all supported distributions.
Update:
The previous updates had an incorrect temporary directory hard-coded in the cvs
binary for 9.1 and 9.2. This update corrects the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:112-1
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
if ( rpm_check( reference:"cvs-1.11.10-0.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.10-0.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK9.1")
 || rpm_exists(rpm:"cvs-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0977", value:TRUE);
}
