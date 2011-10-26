#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15409);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0902", "CVE-2004-0903", "CVE-2004-0904", "CVE-2004-0905", "CVE-2004-0908");

 name["english"] = "RHSA-2004-486: galeon";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mozilla packages that fix a number of security issues are now
  available.

  Mozilla is an open source Web browser, advanced email and newsgroup
  client, IRC chat client, and HTML editor.

  Jesse Ruderman discovered a cross-domain scripting bug in Mozilla. If
  a user is tricked into dragging a javascript link into another frame or
  page, it becomes possible for an attacker to steal or modify sensitive
  information from that site. Additionally, if a user is tricked into
  dragging two links in sequence to another window (not frame), it is
  possible for the attacker to execute arbitrary commands. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0905 to this issue.

  Gael Delalleau discovered an integer overflow which affects the BMP
  handling code inside Mozilla. An attacker could create a carefully crafted
  BMP file in such a way that it would cause Mozilla to crash or execute
  arbitrary code when the image is viewed. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-0904 to
  this issue.

  Georgi Guninski discovered a stack-based buffer overflow in the vCard
  display routines. An attacker could create a carefully crafted vCard file
  in such a way that it would cause Mozilla to crash or execute arbitrary
  code when viewed. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0903 to this issue.

  Wladimir Palant discovered a flaw in the way javascript interacts with
  the clipboard. It is possible that an attacker could use malicious
  javascript code to steal sensitive data which has been copied into the
  clipboard. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0908 to this issue.

  Georgi Guninski discovered a heap based buffer overflow in the "Send
  Page" feature. It is possible that an attacker could construct a link in
  such a way that a user attempting to forward it could result in a crash or
  arbitrary code execution. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2004-0902 to this issue.

  Users of Mozilla should update to these updated packages, which contain
  backported patches and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-486.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the galeon packages";
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
if ( rpm_check( reference:"galeon-1.2.13-5.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-2.1.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-3.0.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"galeon-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0902", value:TRUE);
 set_kb_item(name:"CVE-2004-0903", value:TRUE);
 set_kb_item(name:"CVE-2004-0904", value:TRUE);
 set_kb_item(name:"CVE-2004-0905", value:TRUE);
 set_kb_item(name:"CVE-2004-0908", value:TRUE);
}
if ( rpm_exists(rpm:"galeon-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0902", value:TRUE);
 set_kb_item(name:"CVE-2004-0903", value:TRUE);
 set_kb_item(name:"CVE-2004-0904", value:TRUE);
 set_kb_item(name:"CVE-2004-0905", value:TRUE);
 set_kb_item(name:"CVE-2004-0908", value:TRUE);
}

set_kb_item(name:"RHSA-2004-486", value:TRUE);
