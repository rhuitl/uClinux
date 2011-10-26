#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17252);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1156", "CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0255", "CVE-2005-0527", "CVE-2005-0578", "CVE-2005-0584", "CVE-2005-0585", "CVE-2005-0586", "CVE-2005-0588", "CVE-2005-0589", "CVE-2005-0590", "CVE-2005-0591", "CVE-2005-0592", "CVE-2005-0593");

 name["english"] = "RHSA-2005-176: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated firefox packages that fix various bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Users of Firefox are advised to upgrade to this updated package which
  contains Firefox version 1.0.1 and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-176.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the firefox packages";
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
if ( rpm_check( reference:"firefox-1.0.1-1.4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"firefox-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1156", value:TRUE);
 set_kb_item(name:"CVE-2005-0231", value:TRUE);
 set_kb_item(name:"CVE-2005-0232", value:TRUE);
 set_kb_item(name:"CVE-2005-0233", value:TRUE);
 set_kb_item(name:"CVE-2005-0255", value:TRUE);
 set_kb_item(name:"CVE-2005-0527", value:TRUE);
 set_kb_item(name:"CVE-2005-0578", value:TRUE);
 set_kb_item(name:"CVE-2005-0584", value:TRUE);
 set_kb_item(name:"CVE-2005-0585", value:TRUE);
 set_kb_item(name:"CVE-2005-0586", value:TRUE);
 set_kb_item(name:"CVE-2005-0588", value:TRUE);
 set_kb_item(name:"CVE-2005-0589", value:TRUE);
 set_kb_item(name:"CVE-2005-0590", value:TRUE);
 set_kb_item(name:"CVE-2005-0591", value:TRUE);
 set_kb_item(name:"CVE-2005-0592", value:TRUE);
 set_kb_item(name:"CVE-2005-0593", value:TRUE);
}

set_kb_item(name:"RHSA-2005-176", value:TRUE);
