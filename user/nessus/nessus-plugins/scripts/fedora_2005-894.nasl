#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19740);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2495");
 
 name["english"] = "Fedora Core 4 2005-894: xorg-x11";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-894 (xorg-x11).

X.org X11 is an open source implementation of the X Window System.  It
provides the basic low level functionality which full fledged
graphical user interfaces (GUIs) such as GNOME and KDE are designed
upon.

Update Information:

Updated xorg-x11 packages that fix several integer overflows,
various bugs, are now available for Fedora Core 4.

X.Org X11 is an implementation of the X Window System,
which provides the core functionality for the Linux
graphical desktop.

Several integer overflow bugs were found in the way X.Org
X11 code parses pixmap images. It is possible for a user
to gain elevated privileges by loading a specially crafted
pixmap image. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-2495
to this issue.

Additionally, this update contains:

- Support for some newer models of Intel i945 video
chipsets.

- A fix for a regression caused in the last Xorg update
for Fedora Core 4, which resulted in some Matrox
hardware to fail to initialize properly, which was
introduced in the PCI config space access bugfix from
the previous xorg-x11 update.  The PCI config code
has been updated now to handle BIOS related quirks
of this nature, so this fix may also benefit users of
some other brands of video hardware as well.

- A fix for a memory leak in the X server's shadow
framebuffer code.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xorg-x11 package";
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
if ( rpm_check( reference:"xorg-x11-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-devel-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-font-utils-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xfs-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-twm-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xdm-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-doc-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xdmx-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGL-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Mesa-libGLU-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xvfb-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-sdk-6.8.2-37.FC4.48.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xorg-x11-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2495", value:TRUE);
}
