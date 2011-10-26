#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:025
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18096);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0941");
 
 name["english"] = "SUSE-SA:2005:025: OpenOffice_org";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:025 (OpenOffice_org).


This security update fixes a buffer overflow in OpenOffice_org
Microsoft Word document reader which could allow a remote attacker
sending a handcrafted .doc file to execute code as the user
opening the document in OpenOffice.

This is tracked by the Mitre CVE ID CVE-2005-0941.


WARNING: The updated packages are very large for distributions before
SUSE Linux 9.2 and 9.3.

The minimum download sizes for those are:
SUSE Linux Desktop 1:   47 MB
Novell Linux Desktop 9: 41 MB
SUSE Linux 8.2:         37 MB
SUSE Linux 9.0:         46 MB
SUSE Linux 9.1:         50 MB
SUSE Linux 9.2:          2.1 MB (using delta rpm)
SUSE Linux 9.3:          3.5 MB (using delta rpm)


Solution : http://www.suse.de/security/advisories/2005_25_openoffice_org.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the OpenOffice_org package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"OpenOffice_org-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-help-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-1.0.2-76", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-help-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-1.1-100", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-help-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-1.1.1-23.6", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ca-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-en-help-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fi-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gnome-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-kde-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-1.1.3-16.2", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ar-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ca-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-cs-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-da-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-de-templates-8.2-157", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-el-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-es-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-et-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fi-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-fr-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-gnome-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-hu-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-it-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ja-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-kde-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ko-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-nl-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pl-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-pt-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-ru-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sk-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sl-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-sv-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-tr-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-CN-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"OpenOffice_org-zh-TW-1.9.79-9.2", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"OpenOffice_org-", release:"SUSE8.2")
 || rpm_exists(rpm:"OpenOffice_org-", release:"SUSE9.0")
 || rpm_exists(rpm:"OpenOffice_org-", release:"SUSE9.1")
 || rpm_exists(rpm:"OpenOffice_org-", release:"SUSE9.2")
 || rpm_exists(rpm:"OpenOffice_org-", release:"SUSE9.3") )
{
 set_kb_item(name:"CVE-2005-0941", value:TRUE);
}
