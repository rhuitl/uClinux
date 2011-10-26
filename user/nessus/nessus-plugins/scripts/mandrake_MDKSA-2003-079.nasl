#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:079
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14062);
 script_bugtraq_id(8297);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0459");
 
 name["english"] = "MDKSA-2003:079: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:079 (kdelibs).


A vulnerability in Konqueror was discovered where it could inadvertently send
authentication credentials to websites other than the intended site in clear
text via the HTTP-referer header when authentication credentials are passed as
part of a URL in the form http://user:password@host/.
The provided packages have a patch that corrects this issue.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:079
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
if ( rpm_check( reference:"kdelibs-3.0.5a-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.0.5a-1.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.1-58.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.1-58.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.1-58.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-static-devel-3.1-58.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK9.0")
 || rpm_exists(rpm:"kdelibs-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0459", value:TRUE);
}
