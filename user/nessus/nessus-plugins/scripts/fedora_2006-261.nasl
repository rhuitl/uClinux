#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21192);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1550");
 
 name["english"] = "Fedora Core 4 2006-261: dia";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-261 (dia).

The Dia drawing program is designed to be like the Windows(TM) Visio
program.  Dia can be used to draw different types of diagrams, and
includes support for UML static structure diagrams (class diagrams),
entity relationship modeling, and network diagrams.  Dia can load and
save diagrams to a custom file format, can load and save in .xml format,
and can export to PostScript(TM).

Update Information:

Fixes CVE-2006-1550 Dia multiple buffer overflows


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dia package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"dia-0.94-13.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dia-debuginfo-0.94-13.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"dia-", release:"FC4") )
{
 set_kb_item(name:"CVE-2006-1550", value:TRUE);
}
