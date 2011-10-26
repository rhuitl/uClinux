# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20103);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200510-21");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-21
(phpMyAdmin: Local file inclusion and XSS vulnerabilities)


    Stefan Esser discovered that by calling certain PHP files
    directly, it was possible to workaround the grab_globals.lib.php
    security model and overwrite the $cfg configuration array. Systems
    running PHP in safe mode are not affected. Futhermore, Tobias Klein
    reported several cross-site-scripting issues resulting from
    insufficient user input sanitizing.
  
Impact

    A local attacker may exploit this vulnerability by sending
    malicious requests, causing the execution of arbitrary code with the
    rights of the user running the web server. Furthermore, the cross-site
    scripting issues give a remote attacker the ability to inject and
    execute malicious script code or to steal cookie-based authentication
    credentials, potentially compromising the victim\'s browser.
  
Workaround

    There is no known workaround for all those issues at this time.
  
References:
    http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-5


Solution: 
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.6.4_p3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-21] phpMyAdmin: Local file inclusion and XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Local file inclusion and XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.6.4_p3"), vulnerable: make_list("lt 2.6.4_p3")
)) { security_warning(0); exit(0); }
