#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19655);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0806");
 
 name["english"] = "Fedora Core 3 2005-338: evolution";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-338 (evolution).

Evolution is the GNOME mailer, calendar, contact manager and
communications tool.  The tools which make up Evolution will
be tightly integrated with one another and act as a seamless
personal information-management tool.


* Fri Apr 22 2005 David Malcolm <dmalcolm redhat com> - 2.0.4-4

- Added the correct patch this time

* Wed Apr 20 2005 David Malcolm <dmalcolm redhat com> - 2.0.4-3

- Added patch for #155378 (CVE-2005-0806)
- Updated mozilla_build_version from 1.7.6 to 1.7.7




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the evolution package";
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
if ( rpm_check( reference:"evolution-2.0.4-4", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.4-4", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"evolution-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0806", value:TRUE);
}
