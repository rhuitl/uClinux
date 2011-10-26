#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22358);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");

 name["english"] = "RHSA-2006-0676: seamonkey";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated seamonkey packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 2.1, 3, and 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  SeaMonkey is an open source Web browser, advanced email and newsgroup
  client, IRC chat client, and HTML editor.

  Two flaws were found in the way SeaMonkey processed certain regular
  expressions. A malicious web page could crash the browser or possibly
  execute arbitrary code as the user running SeaMonkey. (CVE-2006-4565,
  CVE-2006-4566)

  A flaw was found in the handling of Javascript timed events. A malicious
  web page could crash the browser or possibly execute arbitrary code as the
  user running SeaMonkey. (CVE-2006-4253)

  Daniel Bleichenbacher recently described an implementation error in RSA
  signature verification. For RSA keys with exponent 3 it is possible for an
  attacker to forge a signature that would be incorrectly verified by the NSS
  library. SeaMonkey as shipped trusts several root Certificate Authorities
  that use exponent 3. An attacker could have created a carefully crafted
  SSL certificate which be incorrectly trusted when their site was visited by
  a victim. (CVE-2006-4340)

  SeaMonkey did not properly prevent a frame in one domain from injecting
  content into a sub-frame that belongs to another domain, which facilitates
  website spoofing and other attacks (CVE-2006-4568)

  A flaw was found in SeaMonkey Messenger triggered when a HTML message
  contained a remote image pointing to a XBL script. An attacker could have
  created a carefully crafted message which would execute Javascript if
  certain actions were performed on the email by the recipient, even if
  Javascript was disabled. (CVE-2006-4570)

  A number of flaws were found in SeaMonkey. A malicious web page could
  crash the browser or possibly execute arbitrary code as the user running
  SeaMonkey. (CVE-2006-4571)

  Users of SeaMonkey or Mozilla are advised to upgrade to this update, which
  contains SeaMonkey version 1.0.5 that corrects these issues.

  For users of Red Hat Enterprise Linux 2.1 this SeaMonkey update obsoletes
  Galeon. Galeon was a web browser based on the Mozilla Gecko layout engine.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0676.html
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
if ( rpm_check( reference:"seamonkey-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-chat-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-devel-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-js-debugger-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-devel-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-devel-1.0.5-0.0.1.el2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-chat-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-devel-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-js-debugger-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-devel-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-devel-1.0.5-0.1.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"devhelp-0.10-0.4.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.10-0.4.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-chat-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-devel-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-js-debugger-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-devel-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-devel-1.0.5-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"seamonkey-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-4253", value:TRUE);
 set_kb_item(name:"CVE-2006-4340", value:TRUE);
 set_kb_item(name:"CVE-2006-4565", value:TRUE);
 set_kb_item(name:"CVE-2006-4566", value:TRUE);
 set_kb_item(name:"CVE-2006-4568", value:TRUE);
 set_kb_item(name:"CVE-2006-4570", value:TRUE);
 set_kb_item(name:"CVE-2006-4571", value:TRUE);
}
if ( rpm_exists(rpm:"seamonkey-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-4253", value:TRUE);
 set_kb_item(name:"CVE-2006-4340", value:TRUE);
 set_kb_item(name:"CVE-2006-4565", value:TRUE);
 set_kb_item(name:"CVE-2006-4566", value:TRUE);
 set_kb_item(name:"CVE-2006-4568", value:TRUE);
 set_kb_item(name:"CVE-2006-4570", value:TRUE);
 set_kb_item(name:"CVE-2006-4571", value:TRUE);
}
if ( rpm_exists(rpm:"seamonkey-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4253", value:TRUE);
 set_kb_item(name:"CVE-2006-4340", value:TRUE);
 set_kb_item(name:"CVE-2006-4565", value:TRUE);
 set_kb_item(name:"CVE-2006-4566", value:TRUE);
 set_kb_item(name:"CVE-2006-4568", value:TRUE);
 set_kb_item(name:"CVE-2006-4570", value:TRUE);
 set_kb_item(name:"CVE-2006-4571", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0676", value:TRUE);
