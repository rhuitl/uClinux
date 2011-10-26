#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12397);
 script_version ("$Revision: 1.4 $");

 name["english"] = "RHSA-2003-177: rhn_register";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated versions of the rhn_register and up2date packages are now
  available. The new packages include many bug fixes, and a few new features.

  The rhn_register and up2date packages contain the software necessary to
  take advantage of Red Hat Network functionality.

  The up2date package incorporates improvements in handling package
  dependencies and "obsoletes" processing, along with many other bug fixes.

  This release also includes an updated RHNS-CA-CERT file, which contains an
  additional CA certificate. This is needed so that up2date can continue to
  communicate with Red Hat Network once the current CA certificate reaches
  its August 2003 expiration date.

  All users of Red Hat Network should therefore upgrade to these erratum
  packages.




Solution : http://rhn.redhat.com/errata/RHSA-2003-177.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rhn_register packages";
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
if ( rpm_check( reference:"rhn_register-2.8.34-1.2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rhn_register-gnome-2.8.34-1.2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"up2date-2.8.45-1.2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"up2date-gnome-2.8.45-1.2.1AS", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}


set_kb_item(name:"RHSA-2003-177", value:TRUE);
