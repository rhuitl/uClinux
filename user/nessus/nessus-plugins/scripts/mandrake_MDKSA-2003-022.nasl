#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:022
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14007);
 script_bugtraq_id(6905);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1336", "CVE-2002-1511");
 
 name["english"] = "MDKSA-2003:022: vnc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:022 (vnc).


A vulnerability was discovered in the VNC server script that generates an X
cookie, used by X authentication. The script generated a cookie that was not
strong enough and allow an attacker to more easily guess the authentication
cookie, thus obtaining unauthorized access to the VNC server.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:022
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vnc package";
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
if ( rpm_check( reference:"vnc-3.3.3-8.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-SVGALIB-3.3.3-8.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-doc-3.3.3-8.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-java-3.3.3-8.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-server-3.3.3-8.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-3.3.3r2-9.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-doc-3.3.3r2-9.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-server-3.3.3r2-9.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-3.3.3r2-9.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-doc-3.3.3r2-9.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-server-3.3.3r2-9.3mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-3.3.3r2-9.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-doc-3.3.3r2-9.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vnc-server-3.3.3r2-9.3mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tightvnc-1.2.5-2.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tightvnc-doc-1.2.5-2.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tightvnc-server-1.2.5-2.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"vnc-", release:"MDK7.2")
 || rpm_exists(rpm:"vnc-", release:"MDK8.0")
 || rpm_exists(rpm:"vnc-", release:"MDK8.1")
 || rpm_exists(rpm:"vnc-", release:"MDK8.2")
 || rpm_exists(rpm:"vnc-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1336", value:TRUE);
 set_kb_item(name:"CVE-2002-1511", value:TRUE);
}
