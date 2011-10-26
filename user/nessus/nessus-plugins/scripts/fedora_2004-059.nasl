#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13672);
 script_bugtraq_id(8780);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0848");
 
 name["english"] = "Fedora Core 1 2004-059: slocate";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-059 (slocate).

Slocate is a security-enhanced version of locate. Just like locate,
slocate searches through a central database (which is updated nightly)
for files which match a given pattern. Slocate allows you to quickly
find files anywhere on your system.

Update Information:

Patrik Hornik discovered a vulnerability in Slocate versions up to and
including 2.7 where a carefully crafted database could overflow a
heap-based buffer. A local user could exploit this vulnerability to gain
'slocate' group privileges and then read the entire slocate database. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
the name CVE-2003-0848 to this issue.

Users of Slocate should upgrade to these packages which contain a
patch from Kevin Lindsay which causes slocate to drop privileges before
reading a user-supplied database.


Solution : http://www.fedoranews.org/updates/FEDORA-2004-059.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the slocate package";
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
if ( rpm_check( reference:"slocate-2.7-4", prefix:"slocate-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"slocate-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-0848", value:TRUE);
}
