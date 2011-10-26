#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13666);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0024");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0962");
 
 name["english"] = "Fedora Core 1 2003-030: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2003-030 (rsync).

Rsync uses a reliable algorithm to bring remote and host files into
sync very quickly. Rsync is fast because it just sends the differences
in the files over the network instead of sending the complete
files. Rsync is often used as a very powerful mirroring process or
just as a more capable replacement for the rcp command. A technical
report which describes the rsync algorithm is included in this
package.

Update Information:

A heap overflow bug exists in rsync versions prior to 2.5.7.  On
machines where the rsync server has been enabled, a remote attacker
could use this flaw to execute arbitrary code as an unprivileged user.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2003-0962 to this issue.



Solution : http://www.fedoranews.org/updates/FEDORA-2003-030.shtml
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
if ( rpm_check( reference:"rsync-2.5.7-2", prefix:"rsync-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"rsync-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0962", value:TRUE);
}
