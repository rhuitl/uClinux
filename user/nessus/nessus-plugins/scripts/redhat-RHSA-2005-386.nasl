#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18148);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1159", "CVE-2005-1160");

 name["english"] = "RHSA-2005-386: devhelp";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mozilla packages that fix various security bugs are now available.

  This update has been rated as having Important security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  Vladimir V. Perepelitsa discovered a bug in the way Mozilla handles
  anonymous functions during regular expression string replacement. It is
  possible for a malicious web page to capture a random block of browser
  memory. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2005-0989 to this issue.

  Doron Rosenberg discovered a bug in the way Mozilla displays pop-up
  windows. If a user choses to open a pop-up window whose URL is malicious
  javascript, the script will be executed with elevated privileges.
  (CVE-2005-1153)

  A bug was found in the way Mozilla handles the javascript global scope for
  a window. It is possible for a malicious web page to define a global
  variable known to be used by a different site, allowing malicious code to
  be executed in the context of the site. (CVE-2005-1154)

  Michael Krax discovered a bug in the way Mozilla handles favicon links. A
  malicious web page can programatically define a favicon link tag as
  javascript, executing arbitrary javascript with elevated privileges.
  (CVE-2005-1155)

  Michael Krax discovered a bug in the way Mozilla installed search plugins.
  If a user chooses to install a search plugin from a malicious site, the new
  plugin could silently overwrite an existing plugin. This could allow the
  malicious plugin to execute arbitrary code and stealm sensitive
  information. (CVE-2005-1156 CVE-2005-1157)

  A bug was found in the way Mozilla validated several XPInstall related
  javascript objects. A malicious web page could pass other objects to the
  XPInstall objects, resulting in the javascript interpreter jumping to
  arbitrary locations in memory. (CVE-2005-1159)

  A bug was found in the way the Mozilla privileged UI code handled DOM nodes
  from the content window. A malicious web page could install malicious
  javascript code or steal data requiring a user to do commonplace actions
  such as clicking a link or opening the context menu. (CVE-2005-1160)

  Users of Mozilla are advised to upgrade to this updated package which
  contains Mozilla version 1.7.7 to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-386.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the devhelp packages";
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
if ( rpm_check( reference:"devhelp-0.9.2-2.4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.9.2-2.4.4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.7-1.4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"devhelp-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0989", value:TRUE);
 set_kb_item(name:"CVE-2005-1153", value:TRUE);
 set_kb_item(name:"CVE-2005-1154", value:TRUE);
 set_kb_item(name:"CVE-2005-1155", value:TRUE);
 set_kb_item(name:"CVE-2005-1156", value:TRUE);
 set_kb_item(name:"CVE-2005-1157", value:TRUE);
 set_kb_item(name:"CVE-2005-1159", value:TRUE);
 set_kb_item(name:"CVE-2005-1160", value:TRUE);
}

set_kb_item(name:"RHSA-2005-386", value:TRUE);
