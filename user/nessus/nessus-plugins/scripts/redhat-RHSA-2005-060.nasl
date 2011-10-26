#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17176);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0096", "CVE-2005-0097", "CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211", "CVE-2005-0241");

 name["english"] = "RHSA-2005-060: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated Squid package that fixes several security issues is now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Squid is a full-featured Web proxy cache.

  Users of Squid should upgrade to this updated package, which contains
  backported patches, and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-060.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid packages";
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
if ( rpm_check( reference:"squid-2.5.STABLE6-3.4E.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squid-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0094", value:TRUE);
 set_kb_item(name:"CVE-2005-0095", value:TRUE);
 set_kb_item(name:"CVE-2005-0096", value:TRUE);
 set_kb_item(name:"CVE-2005-0097", value:TRUE);
 set_kb_item(name:"CVE-2005-0173", value:TRUE);
 set_kb_item(name:"CVE-2005-0174", value:TRUE);
 set_kb_item(name:"CVE-2005-0175", value:TRUE);
 set_kb_item(name:"CVE-2005-0211", value:TRUE);
 set_kb_item(name:"CVE-2005-0241", value:TRUE);
}

set_kb_item(name:"RHSA-2005-060", value:TRUE);
