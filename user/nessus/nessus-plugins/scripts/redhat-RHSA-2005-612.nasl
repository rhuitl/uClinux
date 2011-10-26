#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19332);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1920");

 name["english"] = "RHSA-2005-612: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelibs packages are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  kdelibs contains libraries for the K Desktop Environment.

  A flaw was discovered affecting Kate, the KDE advanced text editor, and
  Kwrite. Depending on system settings, it may be possible for a local user
  to read the backup files created by Kate or Kwrite. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2005-1920 to
  this issue.

  Please note this issue does not affect Red Hat Enterprise Linux 3 or 2.1.

  Users of Kate or Kwrite should update to these errata packages which
  contains a backported patch from the KDE security team correcting this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-612.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs packages";
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
if ( rpm_check( reference:"kdelibs-3.3.1-3.11", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-3.11", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdelibs-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1920", value:TRUE);
}

set_kb_item(name:"RHSA-2005-612", value:TRUE);
