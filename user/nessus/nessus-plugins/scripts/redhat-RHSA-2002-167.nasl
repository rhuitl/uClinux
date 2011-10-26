#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12318);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0684", "CVE-2002-0391", "CVE-2002-0651");

 name["english"] = "RHSA-2002-167: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated glibc packages are available which fix a buffer overflow in the XDR
  decoder and two vulnerabilities in the resolver functions.

  [updated 8 aug 2002]
  Updated packages have been made available, as the original errata
  introduced
  a bug which could cause calloc() to crash on 32-bit platforms when passed a
  size of 0. These updated errata packages contain a patch to correct this
  bug.

  The glibc package contains standard libraries which are used by
  multiple programs on the system. Sun RPC is a remote procedure call
  framework which allows clients to invoke procedures in a server process
  over a network. XDR is a mechanism for encoding data structures for use
  with RPC. NFS, NIS, and other network services that are built upon Sun
  RPC. The glibc package contains an XDR encoder/decoder derived from Sun\'s
  RPC implementation which was recently demonstrated to be vulnerable to a
  heap overflow.

  An error in the calculation of memory needed for unpacking arrays in the
  XDR decoder can result in a heap buffer overflow in glibc 2.2.5 and
  earlier. Depending upon the application, this vulnerability may be
  exploitable and could lead to arbitrary code execution. (CVE-2002-0391)

  A buffer overflow vulnerability has been found in the way the glibc
  resolver handles the resolution of network names and addresses via DNS (as
  per Internet RFC 1011). Version 2.2.5 of glibc and earlier versions are
  affected. A system would be vulnerable to this issue if the
  "networks" database in the /etc/nsswitch.conf file includes the "dns"
  entry. By default, Red Hat Linux Advanced Server ships with "networks"
  set to "files" and is therefore not vulnerable to this issue.
  (CVE-2002-0684)

  A related issue is a bug in the glibc-compat packages, which
  provide compatibility for applications compiled against glibc version
  2.0.x. Applications compiled against this version (such as those
  distributed with early Red Hat Linux releases 5.0, 5.1, and 5.2) could also
  be vulnerable to this issue. (CVE-2002-0651)

  All users should upgrade to these errata packages which contain patches to
  the glibc libraries and therefore are not vulnerable to these issues.

  Thanks to Solar Designer for providing patches for this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-167.html
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
if ( rpm_check( reference:"glibc-2.2.4-29.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.2.4-29.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-29.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-29.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.4-29.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"glibc-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0684", value:TRUE);
 set_kb_item(name:"CVE-2002-0391", value:TRUE);
 set_kb_item(name:"CVE-2002-0651", value:TRUE);
}

set_kb_item(name:"RHSA-2002-167", value:TRUE);
