#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17177);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1145", "CVE-2004-1165");

 name["english"] = "RHSA-2005-065: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelibs packages that resolve security issues in Konqueror are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the
  Red Hat Security Response Team.

  The kdelibs packages include libraries for the K Desktop Environment.

  Two flaws were found in the sandbox environment used to run Java-applets in
  the Konqueror web browser. If a user has Java enabled in Konqueror and
  visits a malicious website, the website could run a carefully crafted
  Java-applet and obtain escalated privileges allowing reading and writing of
  arbitrary files with the privileges of the victim. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1145 to this issue.

  A flaw was discovered in the FTP kioslave. KDE applications such as
  Konqueror could be forced to execute arbitrary FTP commands via a carefully
  crafted ftp URL. The URL could also be crafted in such a way as to send an
  arbitrary email via SMTP. An attacker could make use of this flaw if a
  victim visits a malicious web site. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2004-1165 to this issue.

  Users should update to these erratum packages which contain backported
  patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-065.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs packages";
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
if ( rpm_check( reference:"kdelibs-3.3.1-3.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-3.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdelibs-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1145", value:TRUE);
 set_kb_item(name:"CVE-2004-1165", value:TRUE);
}

set_kb_item(name:"RHSA-2005-065", value:TRUE);
