#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21181);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3964");

 name["english"] = "RHSA-2006-0272: openmotif";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated openmotif packages that fix a security issue are now available.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  OpenMotif provides libraries which implement the Motif industry standard
  graphical user interface.

  A number of buffer overflow flaws were discovered in OpenMotif\'s libUil
  library. It is possible for an attacker to execute arbitrary code as a
  victim who has been tricked into executing a program linked against
  OpenMotif, which then loads a malicious User Interface Language (UIL) file.
  (CVE-2005-3964)

  Users of OpenMotif are advised to upgrade to these erratum packages, which
  contain a backported security patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0272.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openmotif packages";
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
if ( rpm_check( reference:"openmotif-2.1.30-13.21AS.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.1.30-13.21AS.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-5.RHEL3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-5.RHEL3.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-9.RHEL3.7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-10.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-10.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-11.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openmotif-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-3964", value:TRUE);
}
if ( rpm_exists(rpm:"openmotif-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3964", value:TRUE);
}
if ( rpm_exists(rpm:"openmotif-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3964", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0272", value:TRUE);
