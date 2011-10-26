#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19629);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0638");
 
 name["english"] = "Fedora Core 3 2005-237: xloadimage";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-237 (xloadimage).

The xloadimage utility displays images in an X Window System window,
loads images into the root window, or writes images into a file.
Xloadimage supports many image types (including GIF, TIFF, JPEG, XPM,
and XBM).

Update Information:

This update fixes CVE-2005-0638, a problem in the parsing of shell
metacharacters in filenames. It also fixes bugs in handling of malformed
TIFF and PBM/PNM/PPM issues.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xloadimage package";
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
if ( rpm_check( reference:"xloadimage-4.1-34.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xloadimage-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0638", value:TRUE);
}
