#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18687);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0175", "CVE-2005-0488", "CVE-2005-1175", "CVE-2005-1689");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0027");

 name["english"] = "RHSA-2005-562: krb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated krb5 packages which fix multiple security issues are now available
  for Red Hat Enterprise Linux 2.1 and 3.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Kerberos is a networked authentication system which uses a trusted third
  party (a KDC) to authenticate clients and servers to each other.

  A double-free flaw was found in the krb5_recvauth() routine which may be
  triggered by a remote unauthenticated attacker. Although no exploit is
  currently known to exist, this issue could potentially be exploited to
  allow arbitrary code execution on a Key Distribution Center (KDC). The
  Common Vulnerabilities and Exposures project assigned the name
  CVE-2005-1689 to this issue.

  Daniel Wachdorf discovered a single byte heap overflow in the
  krb5_unparse_name() function, part of krb5-libs. Sucessful exploitation of
  this flaw would lead to a denial of service (crash). To trigger this flaw
  an attacker would need to have control of a kerberos realm that shares a
  cross-realm key with the target, making exploitation of this flaw unlikely.
  (CVE-2005-1175).

  The krb5-libs package contains libkrb5, which implements a majority of the
  Kerberos 5 APIs. The krb5_unparse_name() function may overflow a buffer by
  one byte if it is passed a properly formatted principal name structure.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-1175 to this issue. The krb5_recvauth()
  function may corrupt its heap in certain error cases. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-1689 to this issue.

  Gaël Delalleau discovered an information disclosure issue in the way
  some telnet clients handle messages from a server. An attacker could
  construct a malicious telnet server that collects information from the
  environment of any victim who connects to it using the Kerberos-aware
  telnet client (CVE-2005-0488).

  The rcp protocol allows a server to instruct a client to write to arbitrary
  files outside of the current directory. This could potentially cause a
  security issue if a user uses the Kerberos-aware rcp to copy files from a
  malicious server (CVE-2004-0175).

  All users of krb5 should update to these erratum packages which contain
  backported patches to correct these issues. Red Hat would like to thank
  the MIT Kerberos Development Team for their responsible disclosure of these
  issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-562.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb packages";
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
if ( rpm_check( reference:"krb5-devel-1.2.2-37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-37", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-47", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-47", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-47", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-47", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"krb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0175", value:TRUE);
 set_kb_item(name:"CVE-2005-0488", value:TRUE);
 set_kb_item(name:"CVE-2005-1175", value:TRUE);
 set_kb_item(name:"CVE-2005-1689", value:TRUE);
}
if ( rpm_exists(rpm:"krb-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0175", value:TRUE);
 set_kb_item(name:"CVE-2005-0488", value:TRUE);
 set_kb_item(name:"CVE-2005-1175", value:TRUE);
 set_kb_item(name:"CVE-2005-1689", value:TRUE);
}

set_kb_item(name:"RHSA-2005-562", value:TRUE);
