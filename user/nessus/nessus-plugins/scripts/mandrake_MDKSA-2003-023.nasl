#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:023
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14008);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2002-1405");
 
 name["english"] = "MDKSA-2003:023: lynx";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:023 (lynx).


A vulnerability was discovered in lynx, a text-mode web browser. The HTTP
queries that lynx constructs are from arguments on the command line or the
$WWW_HOME environment variable, but lynx does not properly sanitize special
characters such as carriage returns or linefeeds. Extra headers can be inserted
into the request because of this, which can cause scripts that use lynx to fetch
data from the wrong site from servers that use virtual hosting.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:023
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lynx package";
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
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-0.10mdk.dev.8", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"lynx-", release:"MDK7.2")
 || rpm_exists(rpm:"lynx-", release:"MDK8.0")
 || rpm_exists(rpm:"lynx-", release:"MDK8.1")
 || rpm_exists(rpm:"lynx-", release:"MDK8.2")
 || rpm_exists(rpm:"lynx-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1405", value:TRUE);
}
