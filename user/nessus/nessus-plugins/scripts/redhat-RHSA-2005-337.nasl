#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17628);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0255", "CVE-2005-0399");

 name["english"] = "RHSA-2005-337: thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated thunderbird packages that fix various bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  A buffer overflow bug was found in the way Thunderbird processes GIF
  images. It is possible for an attacker to create a specially crafted GIF
  image, which when viewed by a victim will execute arbitrary code as the
  victim. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2005-0399 to this issue.

  A bug was found in the Thunderbird string handling functions. If a
  malicious website is able to exhaust a system\'s memory, it becomes possible
  to execute arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0255 to this issue.

  Users of Thunderbird are advised to upgrade to this updated package which
  contains Thunderbird version 1.0.2 and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-337.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the thunderbird packages";
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
if ( rpm_check( reference:"thunderbird-1.0.2-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"thunderbird-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0255", value:TRUE);
 set_kb_item(name:"CVE-2005-0399", value:TRUE);
}

set_kb_item(name:"RHSA-2005-337", value:TRUE);
