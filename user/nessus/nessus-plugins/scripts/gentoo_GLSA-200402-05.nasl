# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14449);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200402-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200402-05
( 2.5.6-rc1: possible attack against export.php)


    One component of the phpMyAdmin software package (export.php) does not
    properly verify input that is passed to it from a remote user.  Since the
    input is used to include other files, it is possible to launch a directory
    traversal attack.
  
Impact

    Private information could be gleaned from the remote server if an attacker
    uses a malformed URL such as http://phpmyadmin.example.com/export.php?what=../../../[existing_file]
    In this scenario, the script does not sanitize the "what" argument passed
    to it, allowing directory traversal attacks to take place, disclosing
    the contents of files if the file is readable as the web-server user.
  
Workaround

    The workaround is to either patch the export.php file using the
    referenced CVS patch or upgrade the software via Portage.
  
References:
    http://cvs.sourceforge.net/viewcvs.py/phpmyadmin/phpMyAdmin/export.php?r1=2.3&r2=2.3.2.1


Solution: 
    Users are encouraged to upgrade to phpMyAdmin-2.5.6_rc1:
    # emerge sync
    # emerge -pv ">=dev-db/phpmyadmin-2.5.6_rc1"
    # emerge ">=dev-db/phpmyadmin-2.5.6_rc1"
    # emerge clean
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200402-05]  2.5.6-rc1: possible attack against export.php");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: ' 2.5.6-rc1: possible attack against export.php');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.5.6_rc1"), vulnerable: make_list("le 2.5.5_p1")
)) { security_warning(0); exit(0); }
