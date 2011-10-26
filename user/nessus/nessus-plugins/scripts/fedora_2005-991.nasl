#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20026);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-3011");
 
 name["english"] = "Fedora Core 4 2005-991: texinfo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-991 (texinfo).

Texinfo is a documentation system that can produce both online
information and printed output from a single source file. The GNU
Project uses the Texinfo file format for most of its documentation.

Install texinfo if you want a documentation system for producing both
online and print documentation from the same source file and/or if you
are going to write documentation for the GNU Project.

Update Information:

This package fixes a temporary file name vulnerability in
the texindex program (CVE-2005-3011).


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the texinfo package";
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
if ( rpm_check( reference:"texinfo-4.8-4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"info-4.8-4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"texinfo-debuginfo-4.8-4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"texinfo-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-3011", value:TRUE);
}
