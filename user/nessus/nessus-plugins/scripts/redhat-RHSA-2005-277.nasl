#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17270);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0255");

 name["english"] = "RHSA-2005-277: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mozilla packages that fix a buffer overflow issue are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  A bug was found in the Mozilla string handling functions. If a malicious
  website is able to exhaust a system\'s memory, it becomes possible to
  execute arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0255 to this issue.

  Please note that other security issues have been found that affect Mozilla.
  These other issues have a lower severity, and are therefore planned to be
  released as additional security updates in the future.

  Users of Mozilla should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-277.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla packages";
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
if ( rpm_check( reference:"mozilla-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.3-19.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mozilla-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0255", value:TRUE);
}

set_kb_item(name:"RHSA-2005-277", value:TRUE);
