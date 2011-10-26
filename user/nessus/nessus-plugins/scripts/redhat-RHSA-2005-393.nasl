#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18279);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1046");

 name["english"] = "RHSA-2005-393: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelibs packages that fix a flaw in kimgio input validation are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  KDE is a graphical desktop environment for the X Window System. Konqueror
  is the file manager for the K Desktop Environment.

  A source code audit performed by the KDE security team discovered several
  vulnerabilities in the PCX and other image file format readers.

  A buffer overflow was found in the kimgio library for KDE 3.4.0. An
  attacker could create a carefully crafted PCX image in such a way that it
  would cause kimgio to execute arbitrary code when processing the image.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-1046 to this issue.

  All users of kdelibs should upgrade to these updated packages, which
  contain a backported security patch to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-393.html
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
if ( rpm_check( reference:"kdelibs-3.3.1-3.10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-3.10", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"kdelibs-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1046", value:TRUE);
}

set_kb_item(name:"RHSA-2005-393", value:TRUE);
