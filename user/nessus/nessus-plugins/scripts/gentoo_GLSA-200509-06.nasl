# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19671);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200509-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-06
(Squid: Denial of Service vulnerabilities)


    Certain malformed requests result in a segmentation fault in the
    sslConnectTimeout function, handling of other certain requests trigger
    assertion failures.
  
Impact

    By performing malformed requests an attacker could cause Squid to crash
    by triggering an assertion failure or invalid memory reference.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.squid-cache.org/Versions/v2/2.5/bugs/


Solution: 
    All Squid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-proxy/squid-2.5.10-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-06] Squid: Denial of Service vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-proxy/squid", unaffected: make_list("ge 2.5.10-r2"), vulnerable: make_list("lt 2.5.10-r2")
)) { security_warning(0); exit(0); }
