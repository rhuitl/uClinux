#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14691);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(11186);
 script_cve_id("CVE-2004-0689", "CVE-2004-0721", "CVE-2004-0746");
 
 name["english"] = "Fedora Core 2 2004-293: kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-293 (kdebase).

Core applications for the K Desktop Environment.  Included are: kdm
(replacement for xdm), kwin (window manager), konqueror (filemanager,
web browser, ftp client, ...), konsole (xterm replacement), kpanel
(application starter and desktop pager), kaudio (audio server),
kdehelp (viewer for kde help files, info and man pages), kthememgr
(system for managing alternate theme packages) plus other KDE
components (kcheckpass, kikbd, kscreensaver, kcontrol, kfind,
kfontmanager, kmenuedit).

Update Information:

Andrew Tuitt reported that versions of KDE up to and including 3.2.3 create
temporary directories with predictable names. A local attacker could
prevent KDE applications from functioning correctly, or overwrite files
owned by other users by creating malicious symlinks. The Common
Vulnerabilities and Exposures project has assigned the name CVE-2004-0689
to this issue.

WESTPOINT internet reconnaissance services has discovered that the KDE web
browser Konqueror allows websites to set cookies for certain country
specific secondary top level domains. An attacker within one of the
affected domains could construct a cookie which would be sent to all other
websites within the domain leading to a session fixation attack. This
issue does not affect popular domains such as .co.uk, .co.in, or .com. The
Common Vulnerabilities and Exposures project has assigned the name
CVE-2004-0721 to this issue.

A frame injection spoofing vulnerability has been discovered in the
Konqueror web browser. This issue could allow a malicious website to show
arbitrary content in a named frame of a different browser window. The
Common Vulnerabilities and Exposures project has assigned the name
CVE-2004-0746 to this issue.

All users of KDE are advised to upgrade to these packages,
which contain backported patches from the KDE team for these issues.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-293.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdebase package";
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
if ( rpm_check( reference:"kdebase-3.2.2-6.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.2.2-6.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-debuginfo-3.2.2-6.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdebase-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0689", value:TRUE);
 set_kb_item(name:"CVE-2004-0721", value:TRUE);
 set_kb_item(name:"CVE-2004-0746", value:TRUE);
}
