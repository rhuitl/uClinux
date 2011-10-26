#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20164);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2958");
 
 name["english"] = "Fedora Core 3 2005-1029: libgda";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1029 (libgda).

libgda is a library that eases the task of writing
gnome database programs.


* Wed Oct 26 2005 Caolan McNamara <caolanm redhat com> 1:1.0.4-3.1
- CVE-2005-2958 libgda format string issue




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libgda package";
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
if ( rpm_check( reference:"libgda-1.0.4-3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgda-devel-1.0.4-3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda-mysql-1.0.4-3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda-odbc-1.0.4-3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gda-postgres-1.0.4-3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"libgda-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2958", value:TRUE);
}
