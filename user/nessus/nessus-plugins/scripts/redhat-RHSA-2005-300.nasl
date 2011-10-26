#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17591);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0664");

 name["english"] = "RHSA-2005-300: libexif";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libexif packages that fix a buffer overflow issue are now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The libexif package contains the EXIF library. Applications use this
  library to parse EXIF image files.

  A bug was found in the way libexif parses EXIF tags. An attacker could
  create a carefully crafted EXIF image file which could cause image viewers
  linked against libexif to crash. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-0664 to this issue.

  Users of libexif should upgrade to these updated packages, which contain a
  backported patch and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-300.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libexif packages";
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
if ( rpm_check( reference:"libexif-0.5.12-5.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libexif-devel-0.5.12-5.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libexif-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0664", value:TRUE);
}

set_kb_item(name:"RHSA-2005-300", value:TRUE);
