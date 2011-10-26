#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12302);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0363");

 name["english"] = "RHSA-2002-123: ghostscript";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated packages are available for GNU Ghostscript, which fix a
  vulnerability found during PostScript interpretation.

  Ghostscript is a program for displaying PostScript files or printing them
  to non-PostScript printers.

  An untrusted PostScript file can cause ghostscript to execute arbitrary
  commands due to insufficient checking. Since GNU Ghostscript is often used
  during the course of printing a document (and is run as user \'lp\'), all
  users should install these fixed packages.

  The problem is fixed in the 6.53 source release of GNU Ghostscript, and the
  fix has been backported and applied to the packages referenced by this
  advisory.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2002-0363 to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2002-123.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ghostscript packages";
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
if ( rpm_check( reference:"ghostscript-6.51-16.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ghostscript-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0363", value:TRUE);
}

set_kb_item(name:"RHSA-2002-123", value:TRUE);
