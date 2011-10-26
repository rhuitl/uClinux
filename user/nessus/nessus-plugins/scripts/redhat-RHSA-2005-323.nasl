#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17624);
 script_version ("$Revision: 1.2 $");
 if ( NASL_LEVEL >= 2200 )script_cve_id("CVE-2004-0906", "CVE-2004-1380", "CVE-2004-1613", "CVE-2005-0141", "CVE-2005-0144", "CVE-2005-0147", "CVE-2005-0149", "CVE-2005-0232", "CVE-2005-0399");

 name["english"] = "RHSA-2005-323: galeon";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mozilla packages that fix various bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  Users of Mozilla are advised to upgrade to this updated package which
  contains Mozilla version 1.4.4 and additional backported patches to correct
  these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-323.html
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
if ( rpm_check( reference:"galeon-1.2.13-6.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.4-1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.4-1.3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"galeon-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0906", value:TRUE);
 set_kb_item(name:"CVE-2004-1380", value:TRUE);
 set_kb_item(name:"CVE-2004-1613", value:TRUE);
 set_kb_item(name:"CVE-2005-0141", value:TRUE);
 set_kb_item(name:"CVE-2005-0144", value:TRUE);
 set_kb_item(name:"CVE-2005-0147", value:TRUE);
 set_kb_item(name:"CVE-2005-0149", value:TRUE);
 set_kb_item(name:"CVE-2005-0232", value:TRUE);
 set_kb_item(name:"CVE-2005-0399", value:TRUE);
}
if ( rpm_exists(rpm:"galeon-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0906", value:TRUE);
 set_kb_item(name:"CVE-2004-1380", value:TRUE);
 set_kb_item(name:"CVE-2004-1613", value:TRUE);
 set_kb_item(name:"CVE-2005-0141", value:TRUE);
 set_kb_item(name:"CVE-2005-0144", value:TRUE);
 set_kb_item(name:"CVE-2005-0147", value:TRUE);
 set_kb_item(name:"CVE-2005-0149", value:TRUE);
 set_kb_item(name:"CVE-2005-0232", value:TRUE);
 set_kb_item(name:"CVE-2005-0399", value:TRUE);
}

set_kb_item(name:"RHSA-2005-323", value:TRUE);
