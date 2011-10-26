# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14651);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-04
(Squid: Denial of service when using NTLM authentication)


    Squid 2.5.x versions contain a bug in the functions ntlm_fetch_string() and
    ntlm_get_string() which lack checking the int32_t offset "o" for
    negative values.
  
Impact

    A remote attacker could cause a denial of service situation by sending
    certain malformed NTLMSSP packets if NTLM authentication is enabled.
  
Workaround

    Disable NTLM authentication by removing any "auth_param ntlm program
    ..." directives from squid.conf or use ntlm_auth from Samba-3.x.
  
References:
    http://www1.uk.squid-cache.org/squid/Versions/v2/2.5/bugs/#squid-2.5.STABLE6-ntlm_fetch_string


Solution: 
    All Squid users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-www/squid-2.5.6-r2"
    # emerge ">=net-www/squid-2.5.6-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-04] Squid: Denial of service when using NTLM authentication");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Denial of service when using NTLM authentication');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-proxy/squid", unaffected: make_list("ge 2.5.6-r2", "lt 2.5"), vulnerable: make_list("le 2.5.6-r1")
)) { security_warning(0); exit(0); }
