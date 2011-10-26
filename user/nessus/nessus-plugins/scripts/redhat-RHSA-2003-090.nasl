#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12377);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0007");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0028");

 name["english"] = "RHSA-2003-090: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated glibc packages are available to fix an integer overflow in the XDR
  decoder.

  The glibc package contains standard libraries which are used by
  multiple programs on the system. Sun RPC is a remote procedure call
  framework which allows clients to invoke procedures in a server process
  over a network. XDR is a mechanism for encoding data structures for use
  with RPC. NFS, NIS, and many other network services are built upon Sun
  RPC. The XDR encoder/decoder provided with glibc, derived from Sun\'s RPC
  implementation, was demonstrated to be vulnerable to an integer overflow.

  An integer overflow is present in the xdrmem_getbytes() function of glibc
  2.3.1 and earlier. Depending upon the application, this vulnerability
  could cause buffer overflows and may be exploitable, leading to arbitrary
  code execution.

  All users should upgrade to these errata packages which contain patches to
  the glibc libraries and, therefore, are not vulnerable to these issues.

  Red Hat would like to thank eEye Digital Security for alerting us to this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-090.html
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
if ( rpm_check( reference:"glibc-2.2.4-32.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.2.4-32.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-32.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-32.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.4-32.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"glibc-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0028", value:TRUE);
}

set_kb_item(name:"RHSA-2003-090", value:TRUE);
