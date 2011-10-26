#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:060
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13961);
 script_bugtraq_id(3073, 3074);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2001-1374", "CVE-2001-1375");
 
 name["english"] = "MDKSA-2002:060: tcltk";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:060 (tcltk).


Some problems were discovered with the Tcl/Tk development environment. The
expect application would search for its libraries in /var/tmp prior to searching
in other directories, which could allow a local user to gain root privilege by
writing a trojan library and waiting for the root user to run the mkpasswd
utility. This is fixed in version 5.32 of expect. A similiar vulnerability has
been fixed in the tcltk package which searched for its libraries in the current
working directory prior to searching in other directories. This could be used to
execute arbitrary code by local users through the use of a trojan library.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:060
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tcltk package";
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
if ( rpm_check( reference:"expect-8.3.3-21.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"itcl-8.3.3-21.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcl-8.3.3-21.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcllib-8.3.3-21.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tclx-8.3.3-21.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tix-8.3.3-21.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tk-8.3.3-21.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"expect-8.3.3-21.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"itcl-8.3.3-21.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcl-8.3.3-21.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcllib-8.3.3-21.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tclx-8.3.3-21.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tix-8.3.3-21.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tk-8.3.3-21.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"expect-8.3.3-21.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"itcl-8.3.3-21.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcl-8.3.3-21.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcllib-8.3.3-21.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tclx-8.3.3-21.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tix-8.3.3-21.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tk-8.3.3-21.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"expect-8.3.3-21.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"itcl-8.3.3-21.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcl-8.3.3-21.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tcllib-8.3.3-21.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tclx-8.3.3-21.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tix-8.3.3-21.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tk-8.3.3-21.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"tcltk-", release:"MDK7.2")
 || rpm_exists(rpm:"tcltk-", release:"MDK8.0")
 || rpm_exists(rpm:"tcltk-", release:"MDK8.1")
 || rpm_exists(rpm:"tcltk-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2001-1374", value:TRUE);
 set_kb_item(name:"CVE-2001-1375", value:TRUE);
}
