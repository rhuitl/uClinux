#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19380);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2002-1914");

 name["english"] = "RHSA-2005-583: dump";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated dump packages that address two security issues are now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Dump examines files in a file system, determines which ones need to be
  backed up, and copies those files to a specified disk, tape, or other
  storage medium.

  A flaw was found with dump file locking. A malicious local user could
  manipulate the file lock in such a way as to prevent dump from running.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
  the name CVE-2002-1914 to this issue.

  Users of dump should upgrade to these erratum packages, which contain a
  patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-583.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the dump packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"dump-0.4b25-1.72.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rmt-0.4b25-1.72.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"dump-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1914", value:TRUE);
}

set_kb_item(name:"RHSA-2005-583", value:TRUE);
