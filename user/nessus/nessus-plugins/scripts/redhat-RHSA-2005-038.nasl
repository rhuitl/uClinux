#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16160);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1316");

 name["english"] = "RHSA-2005-038: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mozilla packages that fix a buffer overflow issue are now available.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  iSEC Security Research has discovered a buffer overflow bug in the way
  Mozilla handles NNTP URLs. If a user visits a malicious web page or is
  convinced to click on a malicious link, it may be possible for an attacker
  to execute arbitrary code on the victim\'s machine. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1316 to this issue.

  Users of Mozilla should upgrade to these updated packages, which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-038.html
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
if ( rpm_check( reference:"mozilla-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-2.1.5", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-3.0.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mozilla-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1316", value:TRUE);
}
if ( rpm_exists(rpm:"mozilla-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1316", value:TRUE);
}

set_kb_item(name:"RHSA-2005-038", value:TRUE);
