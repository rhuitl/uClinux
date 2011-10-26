#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:071
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13971);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0836");
 
 name["english"] = "MDKSA-2002:071: kdegraphics";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:071 (kdegraphics).


A vulnerability exists in KGhostview, part of the kdegraphics package. It
includes a DSC 3.0 parser from GSview then is vulnerable to a buffer overflow
while parsing a specially crafted .ps file. It also contains code from gv which
is vulnerable to a similar buffer overflow triggered by malformed PostScript and
PDF files. This has been fixed in KDE 3.0.4 and patches have been applied to
correct these packages.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:071
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdegraphics package";
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
if ( rpm_check( reference:"kdegraphics-2.2.1-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-static-devel-2.2.1-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-2.2.2-15.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-2.2.2-15.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-3.0.3-11.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.0.3-11.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdegraphics-", release:"MDK8.1")
 || rpm_exists(rpm:"kdegraphics-", release:"MDK8.2")
 || rpm_exists(rpm:"kdegraphics-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-0836", value:TRUE);
}
