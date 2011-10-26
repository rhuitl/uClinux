#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:041
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19250);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "SUSE-SA:2005:041: php/pear XML::RPC";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:041 (php/pear XML::RPC).


A bug in the PEAR::XML_RPC library allowed remote attackers to
pass arbitrary PHP code to the eval() function.

The updated php packages fix the XML::RPC bug, however several third
party PHP packages include a copy of the problematic XML::RPC code
itself and might be still vulnerable after the update.

Please check their respective websites whether the package is
vulnerable.

The following projects are known to include the XML::RPC code:
	- tikiwiki
	- postnuke
	- drupal
	- b2evolution
	- b2
	- phpGroupWare
	- eGroupware
	- Serendipity Weblog
	- phpAdsNew
	- Max Media Manager

This issue is tracked by the Mitre CVE ID CVE-2005-1921.

The bug in the SUSE php packages affects SUSE Linux versions from 8.2
up to 9.3, SUSE Linux Enterprise Server 9 and Open Enterprise Server.

php4 on SUSE Linux Enterprise Server 8 is not affected, since it was
not shipping the XML::RPC extension.


Solution : http://www.suse.de/security/advisories/2005_41_php_pear.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php/pear XML::RPC package";
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
if ( rpm_check( reference:"apache2-mod_php4-4.3.1-180", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.1-180", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-aolserver-4.3.1-180", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.1-180", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-devel-4.3.1-180", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.3-191", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.3-191", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-aolserver-4.3.3-191", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.3-191", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-devel-4.3.3-191", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.3-191", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-imap-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mysql-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-recode-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-servlet-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-wddx-4.3.4-43.36", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.8-8.9", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php5-5.0.3-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.10-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-5.0.3-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-devel-5.0.3-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-exif-5.0.3-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-fastcgi-5.0.3-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-pear-5.0.3-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-sysvmsg-5.0.3-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php5-sysvshm-5.0.3-14.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
