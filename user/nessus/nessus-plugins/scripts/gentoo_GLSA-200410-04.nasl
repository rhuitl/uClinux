# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15429);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-04
(PHP: Memory disclosure and arbitrary location file upload)


    Stefano Di Paola discovered two bugs in PHP. The first is a parse error in
    php_variables.c that could allow a remote attacker to view the contents of
    the target machine\'s memory. Additionally, an array processing error in the
    SAPI_POST_HANDLER_FUNC() function inside rfc1867.c could lead to the
    $_FILES array being overwritten.
  
Impact

    A remote attacker could exploit the first vulnerability to view memory
    contents. On a server with a script that provides file uploads, an attacker
    could exploit the second vulnerability to upload files to an arbitrary
    location. On systems where the HTTP server is allowed to write in a
    HTTP-accessible location, this could lead to remote execution of arbitrary
    commands with the rights of the HTTP server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/12560/
    http://www.securityfocus.com/archive/1/375294
    http://www.securityfocus.com/archive/1/375370


Solution: 
    All PHP, mod_php and php-cgi users should upgrade to the latest stable
    version:
    # emerge sync
    # emerge -pv ">=dev-php/php-4.3.9"
    # emerge ">=dev-php/php-4.3.9"
    # emerge -pv ">=dev-php/mod_php-4.3.9"
    # emerge ">=dev-php/mod_php-4.3.9"
    # emerge -pv ">=dev-php/php-cgi-4.3.9"
    # emerge ">=dev-php/php-cgi-4.3.9"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-04] PHP: Memory disclosure and arbitrary location file upload");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Memory disclosure and arbitrary location file upload');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.3.9 "), vulnerable: make_list("lt 4.3.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9")
)) { security_warning(0); exit(0); }
