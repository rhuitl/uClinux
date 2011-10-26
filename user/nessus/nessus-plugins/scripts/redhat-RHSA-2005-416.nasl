#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18421);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2003-0644");

 name["english"] = "RHSA-2005-416: kdbg";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated kdbg package that fixes a minor security issue is now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Kdbg is a K Desktop Environment (KDE) GUI for gdb, the GNU debugger.

  Kdbg 1.1.0 through 1.2.8 does not check permissions of the .kdbgrc file.
  If a program is located in a world-writable location, it is possible for a
  local user to inject malicious commands. These commands are then executed
  with the permission of any user that runs Kdbg. The Common Vulnerabilities
  and Exposures project assigned the name CVE-2003-0644 to this issue.

  Users of Kdbg should upgrade to this updated package, which contains a
  backported patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-416.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdbg packages";
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
if ( rpm_check( reference:"kdbg-1.2.1-7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdbg-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0644", value:TRUE);
}

set_kb_item(name:"RHSA-2005-416", value:TRUE);
