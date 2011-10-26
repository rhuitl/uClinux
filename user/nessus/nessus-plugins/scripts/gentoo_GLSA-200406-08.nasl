# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14519);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-08");
 script_xref(name: "CERT", value: "CA-2000-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-08
(Squirrelmail: Another XSS vulnerability)


    A new cross-site scripting (XSS) vulnerability in Squirrelmail-1.4.3_rc1
    has been discovered. In functions/mime.php Squirrelmail fails to properly
    sanitize user input.
  
Impact

    By enticing a user to read a specially crafted e-mail, an attacker can
    execute arbitrary scripts running in the context of the victim\'s browser.
    This could lead to a compromise of the user\'s webmail account, cookie
    theft, etc.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt
    http://www.cert.org/advisories/CA-2000-02.html


Solution: 
    All SquirrelMail users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=mail-client/squirrelmail-1.4.3"
    # emerge ">=mail-client/squirrelmail-1.4.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-08] Squirrelmail: Another XSS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squirrelmail: Another XSS vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/squirrelmail", unaffected: make_list("ge 1.4.3"), vulnerable: make_list("le 1.4.3_rc1-r1")
)) { security_warning(0); exit(0); }
