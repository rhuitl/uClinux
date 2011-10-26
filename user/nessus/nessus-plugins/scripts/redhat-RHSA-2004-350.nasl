#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14595);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0027");
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644");

 name["english"] = "RHSA-2004-350: krb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated krb5 packages that improve client responsiveness and fix several
  security issues are now available for Red Hat Enterprise Linux 3.

  Kerberos is a networked authentication system that uses a trusted third
  party (a KDC) to authenticate clients and servers to each other.

  Several double-free bugs were found in the Kerberos 5 KDC and libraries. A
  remote attacker could potentially exploit these flaws to execuate arbitrary
  code. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CVE-2004-0642 and CVE-2004-0643 to these issues.

  A double-free bug was also found in the krb524 server (CVE-2004-0772),
  however this issue does not affect Red Hat Enterprise Linux 3 Kerberos
  packages.

  An infinite loop bug was found in the Kerberos 5 ASN.1 decoder library. A
  remote attacker may be able to trigger this flaw and cause a denial of
  service. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2004-0644 to this issue.

  When attempting to contact a KDC, the Kerberos libraries will iterate
  through the list of configured servers, attempting to contact each in turn.
  If one of the servers becomes unresponsive, the client will time out and
  contact the next configured server. When the library attempts to contact
  the next KDC, the entire process is repeated. For applications which must
  contact a KDC several times, the accumulated time spent waiting can become
  significant.

  This update modifies the libraries, notes which server for a given realm
  last responded to a request, and attempts to contact that server first
  before contacting any of the other configured servers.

  All users of krb5 should upgrade to these updated packages, which contain
  backported security patches to resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-350.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb packages";
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
if ( rpm_check( reference:"krb5-devel-1.2.7-28", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-28", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-28", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-28", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"krb-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0642", value:TRUE);
 set_kb_item(name:"CVE-2004-0643", value:TRUE);
 set_kb_item(name:"CVE-2004-0644", value:TRUE);
}

set_kb_item(name:"RHSA-2004-350", value:TRUE);
