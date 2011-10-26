#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19677);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2871");

 name["english"] = "RHSA-2005-769: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated mozilla package that fixes a security bug is now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  A bug was found in the way Mozilla processes certain international domain
  names. An attacker could create a specially crafted HTML file, which when
  viewed by the victim would cause Mozilla to crash or possibly execute
  arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-2871 to this issue.

  Users of Mozilla are advised to upgrade to this updated package that
  contains a backported patch and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-769.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla packages";
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
if ( rpm_check( reference:"mozilla-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.10-1.1.2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.10-1.1.3.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.10-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mozilla-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
}
if ( rpm_exists(rpm:"mozilla-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
}
if ( rpm_exists(rpm:"mozilla-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2871", value:TRUE);
}

set_kb_item(name:"RHSA-2005-769", value:TRUE);
