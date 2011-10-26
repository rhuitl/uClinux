#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18388);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1476", "CVE-2005-1477", "CVE-2005-1531", "CVE-2005-1532");

 name["english"] = "RHSA-2005-435: galeon";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mozilla packages that fix various security bugs are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  Several bugs were found in the way Mozilla executes javascript code.
  Javascript executed from a web page should run with a restricted access
  level, preventing dangerous actions. It is possible that a malicious web
  page could execute javascript code with elevated privileges, allowing
  access to protected data and functions. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CVE-2005-1476,
  CVE-2005-1477, CVE-2005-1531, and CVE-2005-1532 to these issues.

  Users of Mozilla are advised to upgrade to this updated package, which
  contains Mozilla version 1.7.8 to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-435.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the galeon packages";
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
if ( rpm_check( reference:"galeon-1.2.14-1.2.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.8-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.8-1.1.3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.8-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"galeon-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-1476", value:TRUE);
 set_kb_item(name:"CVE-2005-1477", value:TRUE);
 set_kb_item(name:"CVE-2005-1531", value:TRUE);
 set_kb_item(name:"CVE-2005-1532", value:TRUE);
}
if ( rpm_exists(rpm:"galeon-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1476", value:TRUE);
 set_kb_item(name:"CVE-2005-1477", value:TRUE);
 set_kb_item(name:"CVE-2005-1531", value:TRUE);
 set_kb_item(name:"CVE-2005-1532", value:TRUE);
}
if ( rpm_exists(rpm:"galeon-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1476", value:TRUE);
 set_kb_item(name:"CVE-2005-1477", value:TRUE);
 set_kb_item(name:"CVE-2005-1531", value:TRUE);
 set_kb_item(name:"CVE-2005-1532", value:TRUE);
}

set_kb_item(name:"RHSA-2005-435", value:TRUE);
