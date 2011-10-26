#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13695);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0426");
 
 name["english"] = "Fedora Core 1 2004-116: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-116 (rsync).

Rsync uses a reliable algorithm to bring remote and host files into
sync very quickly. Rsync is fast because it just sends the differences
in the files over the network instead of sending the complete
files. Rsync is often used as a very powerful mirroring process or
just as a more capable replacement for the rcp command. A technical
report which describes the rsync algorithm is included in this
package.

Update Information:

Rsync before 2.6.1 does not properly sanitize paths when running a
read/write daemon without using chroot. This could allow a remote attacker
to write files outside of the module's 'path', depending on the privileges
assigned to the rsync daemon. Users not running an rsync daemon, running a
read-only daemon, or running a chrooted daemon are not affected by this
issue. The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2004-0426 to this issue.

Updated packages were made available in June 2004 however the original
update notification email did not make it to fedora-announce-list at
that time.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-116.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rsync package";
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
if ( rpm_check( reference:"rsync-2.5.7-5.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-debuginfo-2.5.7-5.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"rsync-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0426", value:TRUE);
}
