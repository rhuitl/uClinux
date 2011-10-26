#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:069
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20335);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:069: php4,php5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:069 (php4,php5).


Updated PHP packages fix the following security issues:

- Stefan Esser found out that a bug in parse_str() could lead to
activation of register_globals (CVE-2005-3389) and additionally
that file uploads could overwrite $GLOBALS (CVE-2005-3390)

- Bugs in the exif code could lead to a crash (CVE-2005-3353)

- Missing safe_mode checks in image processing code and cURL
functions allowed to bypass safe_mode and open_basedir
(CVE-2005-3391)

- Information leakage via the virtual() function (CVE-2005-3392)

- Missing input sanitation in the mb_send_mail() function
potentially allowed to inject arbitrary mail headers
(CVE-2005-3883)

The previous security update for php caused crashes when mod_rewrite
was used. The updated packages fix that problem as well.


Solution : http://www.suse.de/security/advisories/2005_14_sa.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php4,php5 package";
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
if ( rpm_check( reference:"apache2-mod_php4-4.4.0-6.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php5-5.0.4-9.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.4.0-6.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.4.0-6.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.4.0-6.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mbstring-4.4.0-6.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-servlet-4.4.0-6.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-5.0.4-9.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-exif-5.0.4-9.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-fastcgi-5.0.4-9.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-mbstring-5.0.4-9.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-pear-5.0.4-9.6", release:"SUSE10.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.3-201", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-4.3.3-201", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-aolserver-4.3.3-201", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.3-201", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-devel-4.3.3-201", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.3-201", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-core-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-imap-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mbstring-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mysql-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-recode-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-servlet-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-wddx-4.3.4-43.46.8", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mbstring-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.8-8.19", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php4-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_php5-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"mod_php4-servlet-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-devel-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-exif-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-fastcgi-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-mbstring-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-pear-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-session-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php4-sysvshm-4.3.10-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-devel-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-exif-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-fastcgi-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-mbstring-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-pear-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-sysvmsg-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"php5-sysvshm-5.0.3-14.16", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
