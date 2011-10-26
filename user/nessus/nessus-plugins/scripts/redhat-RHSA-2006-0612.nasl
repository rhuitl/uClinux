#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22201);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3083");

 name["english"] = "RHSA-2006-0612: krb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated krb5 packages are now available for Red Hat Enterprise Linux 4 to
  correct a privilege escalation security flaw.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other through use of symmetric encryption
  and a trusted third party, the KDC.

  A flaw was found where some bundled Kerberos-aware applications would fail
  to check the result of the setuid() call. On Linux 2.6 kernels, the
  setuid() call can fail if certain user limits are hit. A local attacker
  could manipulate their environment in such a way to get the applications to
  continue to run as root, potentially leading to an escalation of
  privileges. (CVE-2006-3083).

  Users are advised to update to these erratum packages which contain a
  backported fix to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0612.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"krb5-devel-1.3.4-33", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.4-33", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.4-33", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.4-33", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"krb-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3083", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0612", value:TRUE);
