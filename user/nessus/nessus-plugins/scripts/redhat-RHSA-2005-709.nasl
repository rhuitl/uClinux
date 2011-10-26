#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19994);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1704", "CVE-2005-1705");

 name["english"] = "RHSA-2005-709: gdb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gdb package that fixes several bugs and minor security issues is
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  GDB, the GNU debugger, allows debugging of programs written in C, C++,
  and other languages by executing them in a controlled fashion, then
  printing their data.

  Several integer overflow bugs were found in gdb. If a user is tricked
  into processing a specially crafted executable file, it may allow the
  execution of arbitrary code as the user running gdb. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-1704 to this issue.

  A bug was found in the way gdb loads .gdbinit files. When a user executes
  gdb, the local directory is searched for a .gdbinit file which is then
  loaded. It is possible for a local user to execute arbitrary commands as
  the victim running gdb by placing a malicious .gdbinit file in a location
  where gdb may be run. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-1705 to this issue.

  This updated package also addresses the following issues:

  - GDB on ia64 had previously implemented a bug fix to work-around a kernel
  problem when creating a core file via gcore. The bug fix caused a
  significant slow-down of gcore.

  - GDB on ia64 issued an extraneous warning when gcore was used.

  - GDB on ia64 could not backtrace over a sigaltstack.

  - GDB on ia64 could not successfully do an info frame for a signal
  trampoline.

  - GDB on AMD64 and Intel EM64T had problems attaching to a 32-bit process.

  - GDB on AMD64 and Intel EM64T was not properly handling threaded
  watchpoints.

  - GDB could not build with gcc4 when -Werror flag was set.

  - GDB had problems printing inherited members of C++ classes.

  - A few updates from mainline sources concerning Dwarf2 partial die in
  cache support, follow-fork support, interrupted syscall support, and
  DW_OP_piece read support.

  All users of gdb should upgrade to this updated package, which resolves
  these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-709.html
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
if ( rpm_check( reference:"gdb-6.3.0.0-1.63", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gdb-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1704", value:TRUE);
 set_kb_item(name:"CVE-2005-1705", value:TRUE);
}

set_kb_item(name:"RHSA-2005-709", value:TRUE);
