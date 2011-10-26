#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17146);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-1999-1572");

 name["english"] = "RHSA-2005-080: cpio";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated cpio package that fixes a umask bug and supports large files
  (>2GB) is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team

  GNU cpio copies files into or out of a cpio or tar archive.

  It was discovered that cpio uses a 0 umask when creating files using the -O
  (archive) option. This creates output files with mode 0666 (all can read
  and write) regardless of the user\'s umask setting. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-1999-1572 to this issue.

  All users of cpio should upgrade to this updated package, which resolves
  this issue, and adds support for large files (> 2GB).




Solution : http://rhn.redhat.com/errata/RHSA-2005-080.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cpio packages";
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
if ( rpm_check( reference:"cpio-2.5-3e.3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"cpio-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-1999-1572", value:TRUE);
}

set_kb_item(name:"RHSA-2005-080", value:TRUE);
