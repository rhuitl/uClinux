#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16018);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0968");

 name["english"] = "RHSA-2004-586: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated glibc packages that address several bugs and implement some
  enhancements are now available.

  The GNU libc packages (known as glibc) contain the standard C libraries
  used by applications.

  This errata fixes several bugs in the GNU C Library.

  Fixes include (in addition to enclosed Bugzilla entries):

  - fixed 32-bit atomic operations on 64-bit powerpc
  - fixed -m32 -I /usr/include/nptl compilation on AMD64
  - NPTL <pthread.h> should now be usable in C++ code or -pedantic -std=c89 C
  - rwlocks are now available also in the _POSIX_C_SOURCE=200112L namespace
  - pthread_once is no longer throw(), as the callback routine might throw
  - pthread_create now correctly returns EAGAIN when thread couldn\'t be
  created because of lack of memory
  - fixed NPTL stack freeing in case of pthread_create failure with detached
  thread
  - fixed pthread_mutex_timedlock on i386 and AMD64
  - Itanium gp saving fix in linuxthreads
  - fixed s390/s390x unwinding tests done during cancellation if stack frames
  are small
  - fixed fnmatch(3) backslash handling
  - fixed out of memory behaviour of syslog(3)
  - resolver ID randomization
  - fixed fim (NaN, NaN)
  - glob(3) fixes for dangling symlinks
  - catchsegv fixed to work with both 32-bit and 64-bit binaries on x86-64,
  s390x and ppc
  - fixed reinitialization of _res when using NPTL stack cache
  - updated bug reporting instructions, removed glibcbug script
  - fixed infinite loop in iconv with some options
  - fixed inet_aton return value
  - CPU friendlier busy waiting in linuxthreads on EM64T and IA-64
  - avoid blocking/masking debug signal in linuxthreads
  - fixed locale program output when neither LC_ALL nor LANG is set
  - fixed using of unitialized memory in localedef
  - fixed mntent_r escape processing
  - optimized mtrace script
  - linuxthread_db fixes on ppc64
  - cfi instructions in x86-64 linuxthreads vfork
  - some _POSIX_C_SOURCE=200112L namespace fixes

  All users of glibc should upgrade to these updated packages, which resolve
  these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-586.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the glibc packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"glibc-2.3.2-95.30", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.3.2-95.30", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.3.2-95.30", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-headers-2.3.2-95.30", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.3.2-95.30", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-utils-2.3.2-95.30", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nptl-devel-2.3.2-95.30", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.3.2-95.30", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"glibc-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0968", value:TRUE);
}

set_kb_item(name:"RHSA-2004-586", value:TRUE);
