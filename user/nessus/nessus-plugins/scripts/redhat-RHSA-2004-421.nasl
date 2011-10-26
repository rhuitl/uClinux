#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14214);
 script_version ("$Revision: 1.10 $");
 if ( NASL_LEVEL >= 2191 ) script_cve_id("CVE-2004-0597", "CVE-2004-0599", "CVE-2004-0718", "CVE-2004-0722", "CVE-2004-0757", "CVE-2004-0758", "CVE-2004-0759", "CVE-2004-0760", "CVE-2004-0761", "CVE-2004-0762", "CVE-2004-0763", "CVE-2004-0764", "CVE-2004-0765");

 name["english"] = "RHSA-2004-421: galeon";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mozilla packages based on version 1.4.3 that fix a number of
  security issues for Red Hat Enterprise Linux are now available.

  Mozilla is an open source Web browser, advanced email and newsgroup
  client, IRC chat client, and HTML editor.

  A number of flaws have been found in Mozilla 1.4 that have been fixed in
  the Mozilla 1.4.3 release.


  All users are advised to update to these erratum packages which contain a
  snapshot of Mozilla 1.4.3 including backported fixes and are not vulnerable
  to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-421.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the galeon packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"galeon-1.2.13-3.2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-2.1.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-3.0.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"galeon-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0597", value:TRUE);
 set_kb_item(name:"CVE-2004-0599", value:TRUE);
 set_kb_item(name:"CVE-2004-0718", value:TRUE);
 set_kb_item(name:"CVE-2004-0722", value:TRUE);
 set_kb_item(name:"CVE-2004-0757", value:TRUE);
 set_kb_item(name:"CVE-2004-0758", value:TRUE);
 set_kb_item(name:"CVE-2004-0759", value:TRUE);
 set_kb_item(name:"CVE-2004-0760", value:TRUE);
 set_kb_item(name:"CVE-2004-0761", value:TRUE);
 set_kb_item(name:"CVE-2004-0762", value:TRUE);
 set_kb_item(name:"CVE-2004-0763", value:TRUE);
 set_kb_item(name:"CVE-2004-0764", value:TRUE);
 set_kb_item(name:"CVE-2004-0765", value:TRUE);
}
if ( rpm_exists(rpm:"galeon-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0597", value:TRUE);
 set_kb_item(name:"CVE-2004-0599", value:TRUE);
 set_kb_item(name:"CVE-2004-0718", value:TRUE);
 set_kb_item(name:"CVE-2004-0722", value:TRUE);
 set_kb_item(name:"CVE-2004-0757", value:TRUE);
 set_kb_item(name:"CVE-2004-0758", value:TRUE);
 set_kb_item(name:"CVE-2004-0759", value:TRUE);
 set_kb_item(name:"CVE-2004-0760", value:TRUE);
 set_kb_item(name:"CVE-2004-0761", value:TRUE);
 set_kb_item(name:"CVE-2004-0762", value:TRUE);
 set_kb_item(name:"CVE-2004-0763", value:TRUE);
 set_kb_item(name:"CVE-2004-0764", value:TRUE);
 set_kb_item(name:"CVE-2004-0765", value:TRUE);
}

set_kb_item(name:"RHSA-2004-421", value:TRUE);
