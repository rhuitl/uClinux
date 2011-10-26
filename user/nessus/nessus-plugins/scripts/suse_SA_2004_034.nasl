#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:034
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14775);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688");
 
 name["english"] = "SUSE-SA:2004:034: XFree86-libs, xshared";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:034 (XFree86-libs, xshared).


Chris Evans reported three vulnerabilities in libXpm which can
be exploited remotely by providing malformed XPM image files.
The function xpmParseColors() is vulnerable to an integer overflow
and a stack-based buffer overflow. The functions ParseAndPutPixels()
as well as ParsePixels() is vulnerable to a stack-based buffer overflow
too.
Additionally Matthieu Herrb found two one-byte buffer overflows.



Solution : http://www.suse.de/security/2004_34_xfree86_libs_xshared.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the XFree86-libs, xshared package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"xshared-4.2.0-267", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0-127", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.0.1-55", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-libs-4.3.99.902-43.31", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"XFree86-libs-", release:"SUSE8.1")
 || rpm_exists(rpm:"XFree86-libs-", release:"SUSE8.2")
 || rpm_exists(rpm:"XFree86-libs-", release:"SUSE9.0")
 || rpm_exists(rpm:"XFree86-libs-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0687", value:TRUE);
 set_kb_item(name:"CVE-2004-0688", value:TRUE);
}
