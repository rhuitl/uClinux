#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:006
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13824);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0083", "CVE-2004-0084", "CVE-2004-0106");
 
 name["english"] = "SuSE-SA:2004:006: xf86/XFree86";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SuSE-SA:2004:006 (xf86/XFree86).


XFree86 is an open-source X Window System implementation that acts
as a client-server-based API between different hardware components
like display, mouse, keyboard and so on.
Several buffer overflows were found in the fontfile code that handles
a user-supplied 'fonts.alias' file. The file is processed with root
privileges and therefore a successful exploitation of these bugs leads
to local root access.

There is no known workaround.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, to apply the update use the command 'rpm -Fhv file.rpm'.

Solution : http://www.suse.de/security/2004_06_xf86.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xf86/XFree86 package";
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
if ( rpm_check( reference:"xf86-4.2.0-257", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"xf86-4.2.0-257", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.3.0-120", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"XFree86-4.3.0.1-46", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"xf86-", release:"SUSE8.0")
 || rpm_exists(rpm:"xf86-", release:"SUSE8.1")
 || rpm_exists(rpm:"xf86-", release:"SUSE8.2")
 || rpm_exists(rpm:"xf86-", release:"SUSE9.0") )
{
 set_kb_item(name:"CVE-2004-0083", value:TRUE);
 set_kb_item(name:"CVE-2004-0084", value:TRUE);
 set_kb_item(name:"CVE-2004-0106", value:TRUE);
}
