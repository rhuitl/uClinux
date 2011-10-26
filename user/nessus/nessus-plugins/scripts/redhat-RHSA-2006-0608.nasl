#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22114);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3113", "CVE-2006-3677", "CVE-2006-3801", "CVE-2006-3802", "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", "CVE-2006-3811", "CVE-2006-3812");

 name["english"] = "RHSA-2006-0608: seamonkey";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated seamonkey packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 3.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  SeaMonkey is an open source Web browser, advanced email and newsgroup
  client, IRC chat client, and HTML editor.

  Several flaws were found in the way SeaMonkey processed certain javascript
  actions. A malicious web page could execute arbitrary javascript
  instructions with the permissions of "chrome", allowing the page to steal
  sensitive information or install browser malware. (CVE-2006-3807,
  CVE-2006-3809, CVE-2006-3812)

  Several denial of service flaws were found in the way SeaMonkey processed
  certain web content. A malicious web page could crash the browser or
  possibly execute arbitrary code as the user running SeaMonkey.
  (CVE-2006-3801, CVE-2006-3677, CVE-2006-3113, CVE-2006-3803, CVE-2006-3805,
  CVE-2006-3806, CVE-2006-3811)

  A buffer overflow flaw was found in the way SeaMonkey Messenger displayed
  malformed inline vcard attachments. If a victim viewed an email message
  containing a carefully crafted vcard, it was possible to execute arbitrary
  code as the user running SeaMonkey Messenger. (CVE-2006-3804)

  Several flaws were found in the way SeaMonkey processed certain javascript
  actions. A malicious web page could conduct a cross-site scripting attack
  or steal sensitive information (such as cookies owned by other domains).
  (CVE-2006-3802, CVE-2006-3810)

  A flaw was found in the way SeaMonkey processed Proxy AutoConfig scripts. A
  malicious Proxy AutoConfig server could execute arbitrary javascript
  instructions with the permissions of "chrome", allowing the page to steal
  sensitive information or install browser malware. (CVE-2006-3808)

  Users of SeaMonkey are advised to upgrade to this update, which contains
  SeaMonkey version 1.0.3 that corrects these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0608.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the seamonkey packages";
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
if ( rpm_check( reference:"seamonkey-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-chat-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-devel-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-js-debugger-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-devel-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-devel-1.0.3-0.el3.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"seamonkey-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3113", value:TRUE);
 set_kb_item(name:"CVE-2006-3677", value:TRUE);
 set_kb_item(name:"CVE-2006-3801", value:TRUE);
 set_kb_item(name:"CVE-2006-3802", value:TRUE);
 set_kb_item(name:"CVE-2006-3803", value:TRUE);
 set_kb_item(name:"CVE-2006-3804", value:TRUE);
 set_kb_item(name:"CVE-2006-3805", value:TRUE);
 set_kb_item(name:"CVE-2006-3806", value:TRUE);
 set_kb_item(name:"CVE-2006-3807", value:TRUE);
 set_kb_item(name:"CVE-2006-3808", value:TRUE);
 set_kb_item(name:"CVE-2006-3809", value:TRUE);
 set_kb_item(name:"CVE-2006-3810", value:TRUE);
 set_kb_item(name:"CVE-2006-3811", value:TRUE);
 set_kb_item(name:"CVE-2006-3812", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0608", value:TRUE);
