# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21094);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-13");
 script_cve_id("CVE-2006-0868");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-13
(PEAR-Auth: Potential authentication bypass)


    Matt Van Gundy discovered that PEAR-Auth did not correctly
    validate data passed to the DB and LDAP containers.
  
Impact

    A remote attacker could possibly exploit this vulnerability to
    bypass the authentication mechanism by injecting specially crafted
    input to the underlying storage containers.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0868


Solution: 
    All PEAR-Auth users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/PEAR-Auth-1.2.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-13] PEAR-Auth: Potential authentication bypass");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PEAR-Auth: Potential authentication bypass');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/PEAR-Auth", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4")
)) { security_warning(0); exit(0); }
