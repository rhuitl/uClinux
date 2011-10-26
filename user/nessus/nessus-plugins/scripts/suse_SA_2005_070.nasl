#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:070
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20369);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:070: ipsec-tools,freeswan,openswan";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:070 (ipsec-tools,freeswan,openswan).


Openswan, Freeswan and raccoon (ipsec-tools) have been updated to fix
crashes in aggressive mode. An attacker might send specially crafted
packets that can crash racoon or Pluto.

The ipsec-tools / racoon crashes are tracked by the Mitre CVE ID
CVE-2005-3732.

The openswan / freeswan crashes are tracked by the Mitre CVE ID
CVE-2005-3671.

SUSE Linux Enterprise Server 8 and SUSE Linux 9.0 contain freeswan
1.x and seem no to be affected by this problem.


Solution : http://www.suse.de/security/advisories/2005_70_ipsec.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ipsec-tools,freeswan,openswan package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ipsec-tools-0.6-4.2", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openswan-2.4.4-1.1", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"freeswan-2.04_1.5.4-1.23", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.3.3-1.9", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.4rc1-3.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openswan-2.2.0-8.4", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ipsec-tools-0.5-5.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"openswan-2.2.0-12.4", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
