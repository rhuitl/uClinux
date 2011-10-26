#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22359);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4570", "CVE-2006-4571");

 name["english"] = "RHSA-2006-0677: thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated thunderbird packages that fix several security bugs are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Two flaws were found in the way Thunderbird processed certain regular
  expressions. A malicious HTML email could cause a crash or possibly
  execute arbitrary code as the user running Thunderbird. (CVE-2006-4565,
  CVE-2006-4566)

  A flaw was found in the Thunderbird auto-update verification system. An
  attacker who has the ability to spoof a victim\'s DNS could get Firefox to
  download and install malicious code. In order to exploit this issue an
  attacker would also need to get a victim to previously accept an
  unverifiable certificate. (CVE-2006-4567)

  A flaw was found in the handling of Javascript timed events. A malicious
  HTML email could crash the browser or possibly execute arbitrary code as
  the user running Thunderbird. (CVE-2006-4253)

  Daniel Bleichenbacher recently described an implementation error in RSA
  signature verification. For RSA keys with exponent 3 it is possible for an
  attacker to forge a signature that which would be incorrectly verified by
  the NSS library. (CVE-2006-4340)

  A flaw was found in Thunderbird that triggered when a HTML message
  contained a remote image pointing to a XBL script. An attacker could have
  created a carefully crafted message which would execute Javascript if
  certain actions were performed on the email by the recipient, even if
  Javascript was disabled. (CVE-2006-4570)

  A number of flaws were found in Thunderbird. A malicious HTML email could
  cause a crash or possibly execute arbitrary code as the user running
  Thunderbird. (CVE-2006-4571)

  Users of Thunderbird are advised to upgrade to this update, which contains
  Thunderbird version 1.5.0.7 that corrects these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0677.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the thunderbird packages";
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
if ( rpm_check( reference:"thunderbird-1.5.0.7-0.1.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"thunderbird-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-4253", value:TRUE);
 set_kb_item(name:"CVE-2006-4340", value:TRUE);
 set_kb_item(name:"CVE-2006-4565", value:TRUE);
 set_kb_item(name:"CVE-2006-4566", value:TRUE);
 set_kb_item(name:"CVE-2006-4567", value:TRUE);
 set_kb_item(name:"CVE-2006-4570", value:TRUE);
 set_kb_item(name:"CVE-2006-4571", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0677", value:TRUE);
