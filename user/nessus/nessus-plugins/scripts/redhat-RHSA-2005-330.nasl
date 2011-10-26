#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17659);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");

 name["english"] = "RHSA-2005-330: krb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated krb5 packages which fix two buffer overflow vulnerabilities in the
  included Kerberos-aware telnet client are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Kerberos is a networked authentication system which uses a trusted third
  party (a KDC) to authenticate clients and servers to each other.

  The krb5-workstation package includes a Kerberos-aware telnet client.
  Two buffer overflow flaws were discovered in the way the telnet client
  handles messages from a server. An attacker may be able to execute
  arbitrary code on a victim\'s machine if the victim can be tricked into
  connecting to a malicious telnet server. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CVE-2005-0468 and
  CVE-2005-0469 to these issues.

  Users of krb5 should update to these erratum packages which contain a
  backported patch to correct this issue.

  Red Hat would like to thank iDEFENSE for their responsible disclosure of
  this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-330.html
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
if ( rpm_check( reference:"krb5-devel-1.2.2-34", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-34", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-34", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-34", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-42", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-42", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-42", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-42", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.3.4-12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.4-12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.4-12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.4-12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"krb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}
if ( rpm_exists(rpm:"krb-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}
if ( rpm_exists(rpm:"krb-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}

set_kb_item(name:"RHSA-2005-330", value:TRUE);
