#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12499);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0411");

 name["english"] = "RHSA-2004-222: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelibs packages that fix telnet URI handler and mailto URI handler
  file vulnerabilities are now available.

  The kdelibs packages include libraries for the K Desktop Environment.

  KDE Libraries include: kdecore (KDE core library), kdeui (user interface),
  kfm (file manager), khtmlw (HTML widget), kio (Input/Output, networking),
  kspell (spelling checker), jscript (javascript), kab (addressbook), kimgio
  (image manipulation). Konqueror is a file manager and Web browser for the
  K Desktop Environment (KDE).

  iDEFENSE identified a vulnerability in the Opera web browser that could
  allow remote attackers to create or truncate arbitrary files. The KDE team
  has found two similar vulnerabilities that also exist in KDE.

  A flaw in the telnet URI handler may allow options to be passed to the
  telnet program, resulting in creation or replacement of files. An attacker
  could create a carefully crafted link such that when opened by a victim it
  creates or overwrites a file with the victim\'s permissions.

  A flaw in the mailto URI handler may allow options to be passed to the
  kmail program. These options could cause kmail to write to the file system
  or to run on a remote X display. An attacker could create a carefully
  crafted link in such a way that access may be obtained to run arbitrary
  code as the victim.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0411 to these issues.

  Note: Red Hat Enterprise Linux 2.1 is only vulnerable to the mailto URI
  flaw as a previous update shipped without a telnet.protocol file.

  All users of KDE are advised to upgrade to these erratum packages, which
  contain a backported patch for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-222.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts packages";
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
if ( rpm_check( reference:"arts-2.2.2-11", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-11", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-11", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-11", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-11", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-3.1.3-6.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.1.3-6.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0411", value:TRUE);
}
if ( rpm_exists(rpm:"arts-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0411", value:TRUE);
}

set_kb_item(name:"RHSA-2004-222", value:TRUE);
