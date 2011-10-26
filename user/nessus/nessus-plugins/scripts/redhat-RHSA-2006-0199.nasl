#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20857);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");

 name["english"] = "RHSA-2006-0199: mozilla";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mozilla packages that fix several security bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  Igor Bukanov discovered a bug in the way Mozilla\'s Javascript interpreter
  dereferences objects. If a user visits a malicious web page, Mozilla could
  crash or execute arbitrary code as the user running Mozilla. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2006-0292 to
  this issue.

  moz_bug_r_a4 discovered a bug in Mozilla\'s XULDocument.persist() function.
  A malicious web page could inject arbitrary RDF data into a user\'s
  localstore.rdf file, which can cause Mozilla to execute arbitrary
  javascript when a user runs Mozilla. (CVE-2006-0296)

  A denial of service bug was found in the way Mozilla saves history
  information. If a user visits a web page with a very long title, it is
  possible Mozilla will crash or take a very long time the next time it is
  run. (CVE-2005-4134)

  Note that the Red Hat Enterprise Linux 3 packages also fix a bug when
  using XSLT to transform documents. Passing DOM Nodes as parameters to
  functions expecting an xsl:param could cause Mozilla to throw an exception.

  Users of Mozilla are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0199.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mozilla packages";
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
if ( rpm_check( reference:"mozilla-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.12-1.1.2.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.12-1.1.3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.12-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mozilla-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-4134", value:TRUE);
 set_kb_item(name:"CVE-2006-0292", value:TRUE);
 set_kb_item(name:"CVE-2006-0296", value:TRUE);
}
if ( rpm_exists(rpm:"mozilla-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-4134", value:TRUE);
 set_kb_item(name:"CVE-2006-0292", value:TRUE);
 set_kb_item(name:"CVE-2006-0296", value:TRUE);
}
if ( rpm_exists(rpm:"mozilla-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-4134", value:TRUE);
 set_kb_item(name:"CVE-2006-0292", value:TRUE);
 set_kb_item(name:"CVE-2006-0296", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0199", value:TRUE);
