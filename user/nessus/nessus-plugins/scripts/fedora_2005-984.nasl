#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20021);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2971");
 
 name["english"] = "Fedora Core 3 2005-984: koffice";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-984 (koffice).

The koffice package contains the KOffice office-type applications for
the K Desktop Environment (KDE) GUI desktop. KOffice contains KWord, a
word processor; KSpread, a spreadsheet; KPresenter, for presentations;
and KChart, a diagram generator.


* Tue Oct 11 2005 Than Ngo <than redhat com> 4:1.4.2-0.FC3.2
- remove security fix which is included in new 1.4.2 upstream

* Thu Sep 29 2005 Than Ngo <than redhat com> 4:1.4.2-0.FC3.1
- update to 1.4.2
- apply upstream patch to fix CVE-2005-2971 kword buffer overflow #169486




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the koffice package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"koffice-1.4.2-0.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-devel-1.4.2-0.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"koffice-i18n-1.4.2-0.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"koffice-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2971", value:TRUE);
}
