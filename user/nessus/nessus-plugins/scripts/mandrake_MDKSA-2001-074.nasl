#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:074
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13889);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:074: WindowMaker";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:074 (WindowMaker).


A buffer overflow exists in the WindowMaker window manager's window title
handling code, as discovered by Alban Hertroys. Many programs, such as web
browsers, set the window title to something obtained from the network, such as
the title of the currently-viewed web page. As such, this buffer overflow could
be exploited remotely. WindowMaker versions above and including 0.65.1 are fixed
upstream; these packages have been patched to correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:074
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the WindowMaker package";
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
if ( rpm_check( reference:"WindowMaker-0.62.1-13.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-devel-0.62.1-13.1mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-0.62.1-18.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-devel-0.62.1-18.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-0.64.0-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"WindowMaker-devel-0.64.0-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-0.64.0-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libwraster2-devel-0.64.0-8.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
