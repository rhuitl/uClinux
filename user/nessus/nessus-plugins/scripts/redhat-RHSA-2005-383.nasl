#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18109);
 script_version ("$Revision: 1.2 $");
# script_cve_id("CVE-2005-0752", "CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160");

 name["english"] = "RHSA-2005-383: firefox";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated firefox packages that fix various security bugs are now available.

  This update has been rated as having Important security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Users of Firefox are advised to upgrade to this updated package which
  contains Firefox version 1.0.3 and is not vulnerable to these issues.


Solution : http://rhn.redhat.com/errata/RHSA-2005-383.html
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
if ( rpm_check( reference:"firefox-1.0.3-1.4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"firefox-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0752", value:TRUE);
 set_kb_item(name:"CVE-2005-0989", value:TRUE);
 set_kb_item(name:"CVE-2005-1153", value:TRUE);
 set_kb_item(name:"CVE-2005-1154", value:TRUE);
 set_kb_item(name:"CVE-2005-1155", value:TRUE);
 set_kb_item(name:"CVE-2005-1156", value:TRUE);
 set_kb_item(name:"CVE-2005-1157", value:TRUE);
 set_kb_item(name:"CVE-2005-1158", value:TRUE);
 set_kb_item(name:"CVE-2005-1159", value:TRUE);
 set_kb_item(name:"CVE-2005-1160", value:TRUE);
}

set_kb_item(name:"RHSA-2005-383", value:TRUE);
