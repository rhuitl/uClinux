#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22357);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4568", "CVE-2006-4569", "CVE-2006-4571");

 name["english"] = "RHSA-2006-0675: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated firefox packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Two flaws were found in the way Firefox processed certain regular
  expressions. A malicious web page could crash the browser or possibly
  execute arbitrary code as the user running Firefox. (CVE-2006-4565,
  CVE-2006-4566)

  A number of flaws were found in Firefox. A malicious web page could crash
  the browser or possibly execute arbitrary code as the user running Firefox.
  (CVE-2006-4571)

  A flaw was found in the handling of Javascript timed events. A malicious
  web page could crash the browser or possibly execute arbitrary code as the
  user running Firefox. (CVE-2006-4253)

  Daniel Bleichenbacher recently described an implementation error in RSA
  signature verification. For RSA keys with exponent 3 it is possible for an
  attacker to forge a signature that would be incorrectly verified by the NSS
  library. Firefox as shipped trusts several root Certificate Authorities
  that use exponent 3. An attacker could have created a carefully crafted
  SSL certificate which be incorrectly trusted when their site was visited by
  a victim. (CVE-2006-4340)

  A flaw was found in the Firefox auto-update verification system. An
  attacker who has the ability to spoof a victim\'s DNS could get Firefox to
  download and install malicious code. In order to exploit this issue an
  attacker would also need to get a victim to previously accept an
  unverifiable certificate. (CVE-2006-4567)

  Firefox did not properly prevent a frame in one domain from injecting
  content into a sub-frame that belongs to another domain, which facilitates
  website spoofing and other attacks (CVE-2006-4568)

  Firefox did not load manually opened, blocked popups in the right domain
  context, which could lead to cross-site scripting attacks. In order to
  exploit this issue an attacker would need to find a site which would frame
  their malicious page and convince the user to manually open a blocked
  popup. (CVE-2006-4569)

  Users of Firefox are advised to upgrade to this update, which contains
  Firefox version 1.5.0.7 that corrects these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0675.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the firefox packages";
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
if ( rpm_check( reference:"firefox-1.5.0.7-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"firefox-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4253", value:TRUE);
 set_kb_item(name:"CVE-2006-4340", value:TRUE);
 set_kb_item(name:"CVE-2006-4565", value:TRUE);
 set_kb_item(name:"CVE-2006-4566", value:TRUE);
 set_kb_item(name:"CVE-2006-4567", value:TRUE);
 set_kb_item(name:"CVE-2006-4568", value:TRUE);
 set_kb_item(name:"CVE-2006-4569", value:TRUE);
 set_kb_item(name:"CVE-2006-4571", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0675", value:TRUE);
