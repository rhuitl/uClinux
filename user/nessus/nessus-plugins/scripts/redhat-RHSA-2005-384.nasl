#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18162);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1159", "CVE-2005-1160");

 name["english"] = "RHSA-2005-384: galeon";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Mozilla packages that fix various security bugs are now available.

  This update has been rated as having Important security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  Users of Mozilla are advised to upgrade to this updated package which
  contains Mozilla version 1.7.7 to correct these issues.


Solution : http://rhn.redhat.com/errata/RHSA-2005-384.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the galeon packages";
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
if ( rpm_check( reference:"galeon-1.2.14-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.7-1.1.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.7-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"galeon-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1156", value:TRUE);
 set_kb_item(name:"CVE-2005-0142", value:TRUE);
 set_kb_item(name:"CVE-2005-0143", value:TRUE);
 set_kb_item(name:"CVE-2005-0146", value:TRUE);
 set_kb_item(name:"CVE-2005-0231", value:TRUE);
 set_kb_item(name:"CVE-2005-0232", value:TRUE);
 set_kb_item(name:"CVE-2005-0233", value:TRUE);
 set_kb_item(name:"CVE-2005-0401", value:TRUE);
 set_kb_item(name:"CVE-2005-0527", value:TRUE);
 set_kb_item(name:"CVE-2005-0578", value:TRUE);
 set_kb_item(name:"CVE-2005-0584", value:TRUE);
 set_kb_item(name:"CVE-2005-0585", value:TRUE);
 set_kb_item(name:"CVE-2005-0586", value:TRUE);
 set_kb_item(name:"CVE-2005-0588", value:TRUE);
 set_kb_item(name:"CVE-2005-0590", value:TRUE);
 set_kb_item(name:"CVE-2005-0591", value:TRUE);
 set_kb_item(name:"CVE-2005-0593", value:TRUE);
 set_kb_item(name:"CVE-2005-0989", value:TRUE);
 set_kb_item(name:"CVE-2005-1153", value:TRUE);
 set_kb_item(name:"CVE-2005-1154", value:TRUE);
 set_kb_item(name:"CVE-2005-1155", value:TRUE);
 set_kb_item(name:"CVE-2005-1156", value:TRUE);
 set_kb_item(name:"CVE-2005-1157", value:TRUE);
 set_kb_item(name:"CVE-2005-1159", value:TRUE);
 set_kb_item(name:"CVE-2005-1160", value:TRUE);
}
if ( rpm_exists(rpm:"galeon-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1156", value:TRUE);
 set_kb_item(name:"CVE-2005-0142", value:TRUE);
 set_kb_item(name:"CVE-2005-0143", value:TRUE);
 set_kb_item(name:"CVE-2005-0146", value:TRUE);
 set_kb_item(name:"CVE-2005-0231", value:TRUE);
 set_kb_item(name:"CVE-2005-0232", value:TRUE);
 set_kb_item(name:"CVE-2005-0233", value:TRUE);
 set_kb_item(name:"CVE-2005-0401", value:TRUE);
 set_kb_item(name:"CVE-2005-0527", value:TRUE);
 set_kb_item(name:"CVE-2005-0578", value:TRUE);
 set_kb_item(name:"CVE-2005-0584", value:TRUE);
 set_kb_item(name:"CVE-2005-0585", value:TRUE);
 set_kb_item(name:"CVE-2005-0586", value:TRUE);
 set_kb_item(name:"CVE-2005-0588", value:TRUE);
 set_kb_item(name:"CVE-2005-0590", value:TRUE);
 set_kb_item(name:"CVE-2005-0591", value:TRUE);
 set_kb_item(name:"CVE-2005-0593", value:TRUE);
 set_kb_item(name:"CVE-2005-0989", value:TRUE);
 set_kb_item(name:"CVE-2005-1153", value:TRUE);
 set_kb_item(name:"CVE-2005-1154", value:TRUE);
 set_kb_item(name:"CVE-2005-1155", value:TRUE);
 set_kb_item(name:"CVE-2005-1156", value:TRUE);
 set_kb_item(name:"CVE-2005-1157", value:TRUE);
 set_kb_item(name:"CVE-2005-1159", value:TRUE);
 set_kb_item(name:"CVE-2005-1160", value:TRUE);
}

set_kb_item(name:"RHSA-2005-384", value:TRUE);
