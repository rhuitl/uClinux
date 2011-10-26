#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12391);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0136");

 name["english"] = "RHSA-2003-150: LPRng";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated LPRng packages resolving a temporary file vulnerability are now
  available.

  LPRng is a print spooler. LPRng includes a program, psbanner, that can be
  used to produce Postscript banner pages to separate print jobs.

  A vulnerability has been found in psbanner, which creates in an insecure
  manner a temporary file with a known filename. An attacker could create a
  symbolic link and cause arbitrary files to be written as the lp user.

  Note: psbanner is not used by the default Red Hat Enterprise Linux LPRng
  configuration.

  Users that have configured LPRng to use psbanner should install these
  updated packages, which contain a patch so that psbanner does not create
  the temporary file.




Solution : http://rhn.redhat.com/errata/RHSA-2003-150.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the LPRng packages";
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
if ( rpm_check( reference:"LPRng-3.7.4-28.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"LPRng-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0136", value:TRUE);
}

set_kb_item(name:"RHSA-2003-150", value:TRUE);
