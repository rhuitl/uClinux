# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19811);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-12");
 script_cve_id("CVE-2005-2491", "CVE-2005-2700");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-12
(Apache, mod_ssl: Multiple vulnerabilities)


    mod_ssl contains a security issue when "SSLVerifyClient optional" is
    configured in the global virtual host configuration (CVE-2005-2700).
    Also, Apache\'s httpd includes a PCRE library, which makes it vulnerable
    to an integer overflow (CVE-2005-2491).
  
Impact

    Under a specific configuration, mod_ssl does not properly enforce the
    client-based certificate authentication directive, "SSLVerifyClient
    require", in a per-location context, which could be potentially used by
    a remote attacker to bypass some restrictions. By creating a specially
    crafted ".htaccess" file, a local attacker could possibly exploit
    Apache\'s vulnerability, which would result in a local privilege
    escalation.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2491
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2700


Solution: 
    All mod_ssl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/mod_ssl-2.8.24"
    All Apache 2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/apache-2.0.54-r15"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-12] Apache, mod_ssl: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache, mod_ssl: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 2.0.54-r15", "lt 2"), vulnerable: make_list("lt 2.0.54-r15")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mod_ssl", unaffected: make_list("ge 2.8.24"), vulnerable: make_list("lt 2.8.24")
)) { security_warning(0); exit(0); }
