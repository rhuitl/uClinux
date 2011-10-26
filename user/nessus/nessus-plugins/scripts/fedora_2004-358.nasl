#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15585);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0888");
 
 name["english"] = "Fedora Core 2 2004-358: gpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-358 (gpdf).

This is GPdf, a viewer for Portable Document Format (PDF) files for
GNOME. GPdf is based on the Xpdf program and uses additional GNOME
libraries for better desktop integration.

GPdf includes the gpdf application, a Bonobo control for PDF display
which can be embedded in Nautilus, and a Nautilus property page for
PDF files.

Update Information:

Update to gpdf 2.8.0, which fixes the CVE-2004-0888 security issue.
Also fixes:
#rh127803# crash with mailto: links
#rh132469# crash with remote documents using gnome-vfs


Solution : http://www.fedoranews.org/updates/FEDORA-2004-358.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpdf package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gpdf-2.8.0-4.1.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gpdf-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
}
