#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:030-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14014);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0102");
 
 name["english"] = "MDKSA-2003:030-1: file";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:030-1 (file).


A memory allocation problem in file was found by Jeff Johnson, and a stack
overflow corruption problem was found by David Endler. These problems have been
corrected in file version 3.41 and likely affect all previous version. These
problems pose a security threat as they can be used to execute arbitrary code by
an attacker under the privileges of another user. Note that the attacker must
first somehow convince the target user to execute file against a specially
crafted file that triggers the buffer overflow in file.
Update:
The 8.2 and 9.0 packages installed data in a different directory than where they
should have been installed, which broke compatability with a small number of
programs. These updated packages place those files back in the appropriate
location.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:030-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the file package";
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
if ( rpm_check( reference:"file-3.41-1.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"file-3.41-1.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"file-", release:"MDK8.2")
 || rpm_exists(rpm:"file-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0102", value:TRUE);
}
