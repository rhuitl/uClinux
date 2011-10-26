#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12313);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0660", "CVE-2002-0728");

 name["english"] = "RHSA-2002-152: libpng";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libpng packages are available that fix a buffer overflow
  vulnerability.

  The libpng package contains a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files. PNG
  is a bit-mapped graphics format similar to the GIF format.

  Versions of libpng prior to 1.0.14 contain a buffer overflow in the
  progressive reader when the PNG datastream contains more IDAT data than
  indicated by the IHDR chunk. Such deliberately malformed datastreams would
  crash applications linked to libpng such as Mozilla that use the
  progressive reading feature.

  Packages within Red Hat Linux Advanced Server , such as Mozilla, make use
  of the shared libpng library, therefore all users are advised to upgrade to
  the errata packages which contain libpng 1.0.14. Libpng 1.0.14 is not
  vulnerable to this issue and contains fixes for other bugs including a
  number of memory leaks.




Solution : http://rhn.redhat.com/errata/RHSA-2002-152.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libpng packages";
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
if ( rpm_check( reference:"libpng-1.0.14-0.7x.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libpng-devel-1.0.14-0.7x.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libpng-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0660", value:TRUE);
 set_kb_item(name:"CVE-2002-0728", value:TRUE);
}

set_kb_item(name:"RHSA-2002-152", value:TRUE);
