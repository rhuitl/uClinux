#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:069
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13969);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-0838");
 
 name["english"] = "MDKSA-2002:069: gv";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:069 (gv).


A buffer overflow was discovered in gv versions 3.5.8 and earlier by Zen Parse.
The problem is triggered by scanning a file and can be exploited by an attacker
sending a malformed PostScript or PDF file. This would result in arbitrary code
being executed with the privilege of the user viewing the file. ggv uses code
derived from gv and has the same vulnerability. These updates provide patched
versions of gv and ggv to fix the vulnerabilities.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:069
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gv package";
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
if ( rpm_check( reference:"ggv-1.1.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-18.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ggv-1.1.0-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-27.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ggv-1.1.94-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-27.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ggv-1.99.9-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-27.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gv-", release:"MDK8.0")
 || rpm_exists(rpm:"gv-", release:"MDK8.1")
 || rpm_exists(rpm:"gv-", release:"MDK8.2")
 || rpm_exists(rpm:"gv-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-0838", value:TRUE);
}
