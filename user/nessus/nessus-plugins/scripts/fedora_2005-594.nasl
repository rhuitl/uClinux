#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19230);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1046", "CVE-2005-1920");
 
 name["english"] = "Fedora Core 3 2005-594: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-594 (kdelibs).

Libraries for the K Desktop Environment.

KDE Libraries include: kdecore (KDE core library), kdeui (user
interface), kfm (file manager), khtmlw (HTML widget), kio
(Input/Output, networking), kspell (spelling checker), jscript
(javascript), kab (addressbook), kimgio (image manipulation).

Update Information:

A flaw was discovered affecting Kate, the KDE advanced text editor,
and
Kwrite. Depending on system settings it may be possible for a local
user
to read the backup files created by Kate or Kwrite. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-1920
to
this issue.

Users of Kate or Kwrite should update to this erratum package which
contains a backported patch from the KDE security team correcting this
issue.


Solution : http://www.fedoranews.org/blog/index.php?p=776
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"kdelibs-3.3.1-2.14.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-2.14.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-debuginfo-3.3.1-2.14.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdelibs-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1046", value:TRUE);
 set_kb_item(name:"CVE-2005-1920", value:TRUE);
}
