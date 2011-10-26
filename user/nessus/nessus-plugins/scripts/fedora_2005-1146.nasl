#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20311);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2005-3193");
 
 name["english"] = "Fedora Core 3 2005-1146: gpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1146 (gpdf).

This is GPdf, a viewer for Portable Document Format (PDF) files for
GNOME. GPdf is based on the Xpdf program and uses additional GNOME
libraries for better desktop integration.

GPdf includes the gpdf application, a Bonobo control for PDF display
which can be embedded in Nautilus, and a Nautilus property page for
PDF files.

Update Information:

Several more flaws were discovered in Xpdf, which is used
internally by gpdf. An attacker could
construct a carefully crafted PDF file that could cause gpdf
to crash or possibly execute arbitrary code when opened. The
Common Vulnerabilities and Exposures project assigned the
name CAN-2005-3193 to these issues.

Users of gpdf should upgrade to this updated package, which
contains a patch to resolve these issues.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpdf package";
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
if ( rpm_check( reference:"gpdf-2.8.2-6.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpdf-debuginfo-2.8.2-6.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gpdf-", release:"FC3") )
{
 set_kb_item(name:"CAN-2005-3193", value:TRUE);
}
