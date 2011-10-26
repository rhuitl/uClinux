#
# backport.inc
#
# $Id: backport.inc,v 1.23 2006/08/03 18:01:14 renaud Exp $
# 
# (C) Tenable Network Security
#
#
# When a security flaw is discovered, many OS vendors do not update the product
# to its latest version, but tend to backport the patches instead. This module
# does a translation between the "fixed" (according to the vendor) products, and
# the latest version number.
#
# Credits: This excellent idea comes is from Laurent FACQ (facq@u-bordeaux.fr) 
# and was initially designed to handle Debian. The idea has then been 
# extended to a broader scope than Debian only.
#
# Usage : 
#  new_banner = get_backport_banner(banner:orig_banner);
#
#
#

function get_backport_banner(banner)
{
 local_var i, j,k,l,backported_versions, real_versions, rx_backported_versions, rx_real_versions, paranoia;

 paranoia = get_kb_item("global_settings/report_paranoia");
 if ( paranoia == "Paranoid" ) return banner;

 

 i = 0;
 j = 0;
 k = 0;
 l = 0;

#
# Debian
#   
rx_backported_versions[k++] = '.*OpenSSH_3\\.4p1 Debian 1:3.4p1-1\\.woody\\.3';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedDebian 1:3.4p1-1.woody.3";


rx_backported_versions[k++] = '.*OpenSSH_3\\.6\\.1p2 Debian 1:3\\.6\\.1p2-3\\.sarge\\.1';
rx_real_versions[l++]        = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedDebian 1:3.6.1p2-3.sarge.1";

backported_versions[i++] = 'OpenSSH_3.8.1p1 Debian-8.sarge.4';
real_versions[j++]        = 'OpenSSH_3.9.99p1 ConvertedDebian';


backported_versions[i++] = "Sendmail 8.12.3/8.12.3/Debian-6.6;";
real_versions[j++]	 = "Sendmail 8.12.10/8.12.10/ConvertedDebian;";

#
# MacOS X
# 

rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p1\\+CAN-2003-0693';
rx_real_versions[l++]	 = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedMacOSX+CAN-2003-0693";

rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p1\\+CAN-2004-0175';
rx_real_versions[l++]	 = "SSH-2.0-OpenSSH_3.7.1p2 ConvertedMacOSX+CAN-2004-0175";
#
# AltLinux 
#
rx_backported_versions[k++] = 'OpenSSH_3\\.6\\.1p2-alt4';
rx_real_versions[l++]       = "SSH-2.0-OpenSSH_3.7.1p2-convertedAlt4";


# 
# FreeBSD
#
rx_backported_versions[k++] = "OpenSSH.*FreeBSD.*(20030916|200[4-9])";
rx_real_versions[l++]       = "OpenSSH_3.7.1p2 ConvertedFreeBSD-20030916";


#
# IBM's Apache
# 
backported_versions[i++]   = "IBM_HTTP_SERVER/1.3.19.4 Apache/1.3.20"; 
real_versions[j++]         = "Apache/1.3.28 (ConvertedIBM)";

rx_backported_versions[k++] = "IBM_HTTP_SERVER/2\.0\.47\.[1-9]\.";
rx_real_versions[l++]	   = "Apache/2.0.49 (ConvertedIBM)";

rx_backported_versions[k++]   = "IBM_HTTP_Server/6\.0\.[0-9] Apache/2.0.47";
rx_real_versions[l++]         = "Apache/2.0.99 (ConvertedIBM)";

backported_versions[i++]   = "IBM_HTTP_SERVER/1.3.19.6 Apache/1.3.20"; 
real_versions[j++]         = "Apache/1.3.29 (ConvertedIBM)";


# woody
backported_versions[i++]   = "Apache/1.3.26 (Unix) Debian GNU/Linux"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDebian)";

# testing
backported_versions[i++]   = "Apache/1.3.33 (Unix) Debian GNU/Linux"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDebian)";

# testing
backported_versions[i++]   = "Apache/2.0.54 (Unix) Debian GNU/Linux"; 
real_versions[j++]         = "Apache/2.0.59 (ConvertedDebian)";

# ZyXEL
backported_versions[i++]   = "SSH-1.5-1.0.0"; 
real_versions[j++]         = "SSH-1.5-9.9.9";

# 
# Red Hat and others backports fixes - we can't always rely on the version 
# number
#

# Red Hat 8.0 and 9.0
backported_versions[i++]   = "Apache/2.0.40 (Red Hat Linux)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedRedHat)";

# ES2.1
backported_versions[i++]   = "Apache/1.3.27 (Unix)  (Red-Hat/Linux)"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedRedHat)";

backported_versions[i++]   = "OpenSSH_3.1p1"; 
real_versions[j++]         = "OpenSSH_3.9.99";

# ES3
backported_versions[i++]   = "Apache/2.0.46 (Red Hat)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedRedHat)";


backported_versions[i++]   = "OpenSSH_3.6.1p2"; 
real_versions[j++]         = "OpenSSH_3.9.99";

# ES4
backported_versions[i++]   = "Apache/2.0.52 (Red Hat)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedRedHat)";

backported_versions[i++]   = "OpenSSH_3.9p1"; 
real_versions[j++]         = "OpenSSH_3.9.99";


# SuSE 8.0, Red Hat 8.0
backported_versions[i++]   = "OpenSSH_3.4p1"; 
real_versions[j++]         = "OpenSSH_3.9.99";

# SuSE 8.x, Red Hat 9.0
backported_versions[i++]   = "OpenSSH_3.5p1"; 
real_versions[j++]         = "OpenSSH_3.9.99";


# SuSE 9.0
backported_versions[i++]   = "Apache/2.0.48 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_3.7.1p2"; 
real_versions[j++]         = "OpenSSH_3.9.99";


# SuSE 9.1
backported_versions[i++]   = "Apache/2.0.49 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_3.8p1"; 
real_versions[j++]         = "OpenSSH_3.9.99";

# SuSE 9.2
backported_versions[i++]   = "Apache/2.0.50 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

# SSH -> Same as ES4

# SuSE 9.3
backported_versions[i++]   = "Apache/2.0.53 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

# SSH -> Same as ES4

# SuSE 10.0
backported_versions[i++]   = "Apache/2.0.54 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.0.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.1p1"; 
real_versions[j++]         = "OpenSSH_4.9.99";

# SuSE 10.1
backported_versions[i++]   = "Apache/2.2.0 (Linux/SuSE)"; 
real_versions[j++]         = "Apache/2.2.99 (ConvertedSuSE)";

backported_versions[i++]   = "OpenSSH_4.2p1"; 
real_versions[j++]         = "OpenSSH_4.9.99";

# Mac OS X
backported_versions[i++]   = "Apache/1.3.33 (Darwin)"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin)";

# Mac OS X Server - Admin
backported_versions[i++]   = "Apache/1.3.27 (Darwin) mod_ssl/2.8.12 OpenSSL/0.9.7b"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin) mod_ssl/2.9.99 OpenSSL/0.9.99z";

# Mac OS X Server
backported_versions[i++]   = "Apache/1.3.27 (Darwin)"; 
real_versions[j++]         = "Apache/1.3.99 (ConvertedDarwin)";


# Fedora FC1
backported_versions[i++]   = "Apache/2.0.50 (Fedora)"; 
real_versions[j++]         = "Apache/2.0.99 (Fedora)";

# Fedora FC2
backported_versions[i++]   = "Apache/2.0.51 (Fedora)"; 
real_versions[j++]         = "Apache/2.0.99 (Fedora)";

# Fedora FC3
backported_versions[i++]   = "Apache/2.0.52 (Fedora)"; 
real_versions[j++]         = "Apache/2.0.99 (Fedora)";

# Fedora FC4
backported_versions[i++]   = "Apache/2.0.54 (Fedora)"; 
real_versions[j++]         = "Apache/2.0.99 (Fedora)";

# Fedora FC5
backported_versions[i++]   = "Apache/2.2.0 (Fedora)"; 
real_versions[j++]         = "Apache/2.2.99 (Fedora)";

for ( i = 0 ; backported_versions[i] ; i ++ )
 { 
 if ( tolower(backported_versions[i]) >< tolower(banner) ) 
	return str_replace(find:backported_versions[i], replace:real_versions[i], string:banner);
 }

 for ( i = 0; rx_backported_versions[i]; i ++ )
 {
  if ( egrep(pattern:rx_backported_versions[i], string:banner, icase:TRUE) ) 
   return ereg_replace(pattern:rx_backported_versions[i], 
		       replace:rx_real_versions[i],
		       string:banner, icase:TRUE);
 }


 return banner;
}




function get_php_version(banner)
{
 local_var www_version, php_version, paranoia;
 paranoia = get_kb_item("global_settings/report_paranoia");

 www_version = banner;
 if ( ! www_version ) return NULL;

 php_version = egrep(pattern:"Server:.*PHP/[0-9].", string:www_version);
 if ( ! php_version ) php_version = egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:www_version);
 if ( ! php_version ) return NULL;

 php_version = ereg_replace(pattern:".*(PHP/[0-9.]*)[^0-9.].*", string:php_version, replace:"\1");
 if ( paranoia == "Paranoid" ) return php_version;

 if ( egrep(pattern:"Server:.*Apache.*\(Red.Hat\)", string:www_version) )
 {
  if ( php_version == "PHP/4.1.2" ) return NULL; # RHEL2.1
  if ( php_version == "PHP/4.3.2" ) return NULL; # RHEL3
  if ( php_version == "PHP/4.3.9" ) return NULL; # RHEL4
 }
 if ( egrep(pattern:"Server:.*Apache.*\(SuSE\)", string:www_version) )
 {
  if ( php_version == "PHP/4.1.0" ) return "PHP/4.2.0"; # SuSE 8.0  - not supported any more
  if ( php_version == "PHP/4.2.2" ) return "PHP/4.3.0"; # SuSE 8.1  - not supported any more

  if ( php_version == "PHP/4.3.1" ) return NULL; # SuSE 8.2
  if ( php_version == "PHP/4.3.3" ) return NULL; # SuSE 9.0
  if ( php_version == "PHP/4.3.4" ) return NULL; # SuSE 9.1
  if ( php_version == "PHP/4.3.8" ) return NULL; # SuSE 9.2
  if ( php_version == "PHP/4.3.10" ) return NULL;# SuSE 9.3
  if ( php_version == "PHP/5.0.3" ) return NULL; # SuSE 9.3
 }
 if ( egrep(pattern:"Server:.*Apache.*\(Darwin\)", string:www_version) )
 {
  if ( php_version == "PHP/4.3.10" ) return NULL; # Mac OS X 10.3 
 }
 if ( egrep(pattern:"Server:.*Apache.*\(Fedora\)", string:www_version) ) 
 {
  if ( php_version == "PHP/4.3.8" ) return php_version; # FC1
  if ( php_version == "PHP/4.3.10" ) return NULL; # FC2 & FC3
  if ( php_version == "PHP/5.0.4" ) return NULL; # FC4
  if ( php_version == "PHP/5.1.2" ) return NULL; # FC5
 }

 return php_version;
}
