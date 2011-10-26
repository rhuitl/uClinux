#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:057
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21115);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0528");
 
 name["english"] = "MDKSA-2006:057: cairo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:057 (cairo).



GNOME Evolution allows remote attackers to cause a denial of service
(persistent client crash) via an attached text file that contains
'Content-Disposition: inline' in the header, and a very long line in the body,
which causes the client to repeatedly crash until the e-mail message is
manually removed, possibly due to a buffer overflow, as demonstrated using an
XML attachment. The underlying issue is in libcairo, which is used by recent
versions of Evolution for message rendering. The Corporate Desktop 3.0 version
of Evolution does not use libcairo and is not vulnerable to this issue. Updated
packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:057
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cairo package";
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
if ( rpm_check( reference:"libcairo2-1.0.0-8.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcairo2-devel-1.0.0-8.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libcairo2-static-devel-1.0.0-8.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cairo-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0528", value:TRUE);
}
