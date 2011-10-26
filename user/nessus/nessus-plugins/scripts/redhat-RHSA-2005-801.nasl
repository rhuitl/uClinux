#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20059);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1704", "CVE-2005-1705");

 name["english"] = "RHSA-2005-801: gdb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gdb package that fixes minor security issues is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GDB, the GNU debugger, allows debugging of programs written in C, C++, and
  other languages by executing them in a controlled fashion, then printing
  their data.

  Several integer overflow bugs were found in gdb. If a user is tricked into
  processing a specially crafted executable file, it may allow the execution
  of arbitrary code as the user running gdb. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-1704 to
  this issue.

  A bug was found in the way gdb loads .gdbinit files. When a user executes
  gdb, the local directory is searched for a .gdbinit file which is then
  loaded. It is possible for a local user to execute arbitrary commands as
  the user running gdb by placing a malicious .gdbinit file in a location
  where gdb may be run. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-1705 to this issue.

  All users of gdb should upgrade to this updated package, which contains
  backported patches that resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-801.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdb packages";
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
if ( rpm_check( reference:"gdb-5.3.90-0.20030710.41.2.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gdb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-1704", value:TRUE);
 set_kb_item(name:"CVE-2005-1705", value:TRUE);
}

set_kb_item(name:"RHSA-2005-801", value:TRUE);
