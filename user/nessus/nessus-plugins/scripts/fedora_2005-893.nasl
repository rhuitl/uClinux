#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19739);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2495");
 
 name["english"] = "Fedora Core 3 2005-893: xorg-x11";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-893 (xorg-x11).

X.org X11 is an open source implementation of the X Window System.  It
provides the basic low level functionality which full fledged
graphical user interfaces (GUIs) such as GNOME and KDE are designed
upon.

Update Information:

Updated xorg-x11 packages that fix several integer
overflows, various bugs, are now available for Fedora
Core 3.

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

- A change to the X server to make it use linux PCI config
space access methods instead of directly touching the
PCI config space registers itself.  This prevents the
X server from causing hardware lockups due accessing
PCI config space at the same time the kernel has it
locked.  This is the latest revision of the PCI config
space access patches, which fix a few regressions
discovered on some hardware with previous patches.

- A fix for a memory leak in the X server's shadow
framebuffer code.

- A problem with the Dutch keyboard layout has been
resolved.

- The open source 'nv' driver for Nvidia hardware has been
updated to the latest version. Additionally, a
workaround has been added to the driver to disable known
unstable acceleration primitives on some GeForce
6200/6600/6800 models.

- Several bugs have been fixed in the Xnest X server.

- DRI is now enabled by default on all ATI Radeon hardware
except for the Radeon 7000/Radeon VE chipsets, which
is known to be unstable for many users currently when
DRI is enabled. Radeon 7000 users can re-enable DRI
if desired by using Option 'DRI' in the device
section of the config file, with the understanding that
we consider it unstable currently.

- Added missing libFS.so and libGLw.so symlinks to the
xorg-x11-devel package, which were inadvertently left
out, causing apps to link to the static versions of these
libraries.

- Fix xfs.init 'fonts.dir: No such file or directory' errors

A number of other issues have also been resolved.  Please
consult the xorg-x11 rpm changelog for a detailed list.




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
if ( rpm_check( reference:"xorg-x11-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-devel-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xfs-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-twm-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xdm-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-libs-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-deprecated-libs-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-doc-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xdmx-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xnest-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-tools-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-xauth-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-Xvfb-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xorg-x11-sdk-6.8.2-1.FC3.45", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"xorg-x11-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2495", value:TRUE);
}
