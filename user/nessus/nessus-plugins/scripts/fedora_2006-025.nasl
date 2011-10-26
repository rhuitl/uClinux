#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20406);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3193", "CVE-2005-3626", "CVE-2005-3627");
 
 name["english"] = "Fedora Core 3 2006-025: gpdf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-025 (gpdf).

This is GPdf, a viewer for Portable Document Format (PDF) files for
GNOME. GPdf is based on the Xpdf program and uses additional GNOME
libraries for better desktop integration.

GPdf includes the gpdf application, a Bonobo control for PDF display
which can be embedded in Nautilus, and a Nautilus property page for
PDF files.

Update Information:

Chris Evans discovered several flaws in the way CUPS
processes PDF files. An attacker could construct a carefully
crafted PDF file that could cause CUPS to crash or possibly
execute arbitrary code when opened. The Common
Vulnerabilities and Exposures project assigned the names
CVE-2005-3624, CVE-2005-3625, CVE-2005-3626, and
CVE-2005-3627 to these issues.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gpdf package";
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
if ( rpm_check( reference:"gpdf-2.8.2-7.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gpdf-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-3193", value:TRUE);
 set_kb_item(name:"CVE-2005-3626", value:TRUE);
 set_kb_item(name:"CVE-2005-3627", value:TRUE);
}
