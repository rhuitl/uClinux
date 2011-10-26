#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12454);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0924");

 name["english"] = "RHSA-2004-031: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated NetPBM packages are available that fix a number of temporary file
  vulnerabilities in the netpbm libraries.

  The netpbm package contains a library of functions that support
  programs for handling various graphics file formats, including .pbm
  (portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
  .ppm (portable pixmaps), and others.

  A number of temporary file bugs have been found in versions of NetPBM.
  These could make it possible for a local user to overwrite or create files
  as a different user who happens to run one of the the vulnerable utilities.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0924 to this issue.

  Users are advised to upgrade to the erratum packages, which contain patches
  from Debian that correct these bugs.




Solution : http://rhn.redhat.com/errata/RHSA-2004-031.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netpbm packages";
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
if ( rpm_check( reference:"netpbm-9.24-9.AS21.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-9.AS21.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-9.AS21.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-11.30.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-11.30.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-11.30.1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"netpbm-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0924", value:TRUE);
}
if ( rpm_exists(rpm:"netpbm-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2003-0924", value:TRUE);
}

set_kb_item(name:"RHSA-2004-031", value:TRUE);
