# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15545);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200410-21");
 script_cve_id("CVE-2004-0885");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-21
(Apache 2, mod_ssl: Bypass of SSLCipherSuite directive)


    A flaw has been found in mod_ssl where the "SSLCipherSuite" directive could
    be bypassed in certain configurations if it is used in a directory or
    location context to restrict the set of allowed cipher suites.
  
Impact

    A remote attacker could gain access to a location using any cipher suite
    allowed by the server/virtual host configuration, disregarding the
    restrictions by "SSLCipherSuite" for that location.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0885
    http://issues.apache.org/bugzilla/show_bug.cgi?id=31505


Solution: 
    All Apache 2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-www/apache-2.0.52"
    # emerge ">=net-www/apache-2.0.52"
    All mod_ssl users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-www/mod_ssl-2.8.20"
    # emerge ">=net-www/mod_ssl-2.8.20"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-21] Apache 2, mod_ssl: Bypass of SSLCipherSuite directive");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2, mod_ssl: Bypass of SSLCipherSuite directive');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/mod_ssl", unaffected: make_list("ge 2.8.20"), vulnerable: make_list("lt 2.8.20")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 2.0.52", "lt 2.0"), vulnerable: make_list("lt 2.0.52")
)) { security_warning(0); exit(0); }
