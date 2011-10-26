#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:076
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13891);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:076: xinetd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:076 (xinetd).


An audit has been performed on the xinetd 2.3.0 source code by Solar Designer
for many different possible vulnerabilities. The 2.3.1 release incorporated his
patches into the xinetd source tree. The audit was very thorough and found and
fixed many problems. This xinetd update includes his audit patch.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:076
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xinetd package";
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
if ( rpm_check( reference:"xinetd-2.3.0-5.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-2.3.0-5.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xinetd-ipv6-2.3.0-5.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
