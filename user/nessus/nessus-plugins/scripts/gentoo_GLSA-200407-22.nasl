# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14555);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-22");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-22
(phpMyAdmin: Multiple vulnerabilities)


    Two serious vulnerabilities exist in phpMyAdmin. The first allows any user
    to alter the server configuration variables (including host, name, and
    password) by appending new settings to the array variables that hold the
    configuration in a GET statement. The second allows users to include
    arbitrary PHP code to be executed within an eval() statement in table name
    configuration settings. This second vulnerability is only exploitable if
    $cfg[\'LeftFrameLight\'] is set to FALSE.
  
Impact

    Authenticated users can alter configuration variables for their running
    copy of phpMyAdmin. The impact of this should be minimal. However, the
    second vulnerability would allow an authenticated user to execute arbitrary
    PHP code with the permissions of the webserver, potentially allowing a
    serious Denial of Service or further remote compromise.
  
Workaround

    The second, more serious vulnerability is only exploitable if
    $cfg[\'LeftFrameLight\'] is set to FALSE. In the default Gentoo installation,
    this is set to TRUE. There is no known workaround for the first.
  
References:
    http://www.securityfocus.com/archive/1/367486


Solution: 
    All phpMyAdmin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-db/phpmyadmin-2.5.7_p1"
    # emerge ">=dev-db/phpmyadmin-2.5.7_p1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-22] phpMyAdmin: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.5.7_p1"), vulnerable: make_list("le 2.5.7")
)) { security_warning(0); exit(0); }
