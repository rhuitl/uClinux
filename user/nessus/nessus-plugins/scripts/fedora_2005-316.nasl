#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19650);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0941");
 
 name["english"] = "Fedora Core 3 2005-316: openoffice.org";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-316 (openoffice.org).

OpenOffice.org is an Open Source, community-developed, multi-platform
office productivity suite.  It includes the key desktop applications,
such as a word processor, spreadsheet, presentation manager, formula
editor and drawing program, with a user interface and feature set
similar to other office suites.  Sophisticated and flexible,
OpenOffice.org also works transparently with a variety of file
formats, including Microsoft Office.

Usage: Simply type 'ooffice' to run OpenOffice.org or select the
requested component (Writer, Calc, Draw, Impress, etc.) from your
desktop menu. The ooffice wrapper script will install a few files in
the user's home, if necessary.

The OpenOffice.org team hopes you enjoy working with OpenOffice.org!

Note: Non-.vor templates covered under the GPL license.

Update Information:

This update fixes many International Input issues with the IIIMF input
framework, and also fixes the CVE-2005-0941 security issue recently made
public.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openoffice.org package";
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
if ( rpm_check( reference:"openoffice.org-1.1.3-11.5.0.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"openoffice.org-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0941", value:TRUE);
}
