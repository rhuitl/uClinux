#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14121);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0592");
 
 name["english"] = "MDKSA-2004:022: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:022 (kdelibs).


Corsaire discovered that a number of HTTP user agents contained a flaw in how
they handle cookies. This flaw could allow an attacker to avoid the path
restrictions specified by a cookie's originator. According to their advisory:
'The cookie specifications detail a path argument that can be used to restrict
the areas of a host that will be exposed to a cookie. By using standard
traversal techniques this functionality can be subverted, potentially exposing
the cookie to scrutiny and use in further attacks.'
This issue was fixed in KDE 3.1.3; the updated packages are patched to protect
against this vulnerability.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:022
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"kdelibs-3.1-58.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.1-58.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.1-58.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-static-devel-3.1-58.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0592", value:TRUE);
}
