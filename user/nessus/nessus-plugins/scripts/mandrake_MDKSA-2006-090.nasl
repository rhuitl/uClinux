#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:090
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21601);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1174");
 
 name["english"] = "MDKSA-2006:090: shadow-utils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:090 (shadow-utils).



A potential security problem was found in the useradd tool when it

creates a new user's mailbox due to a missing argument to the open()

call, resulting in the first permissions of the file being some random

garbage found on the stack, which could possibly be held open for

reading or writing before the proper fchmod() call is executed.



Packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:090
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the shadow-utils package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"shadow-utils-4.0.3-9.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"shadow-utils-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2006-1174", value:TRUE);
}
