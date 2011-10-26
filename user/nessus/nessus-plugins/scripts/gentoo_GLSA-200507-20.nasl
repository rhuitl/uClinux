# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19282);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-20");
 script_cve_id("CVE-2005-2317");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-20
(Shorewall: Security policy bypass)


    Shorewall fails to enforce security policies if configured with
    "MACLIST_DISPOSITION" set to "ACCEPT" or "MACLIST_TTL" set to a value
    greater or equal to 0.
  
Impact

    A client authenticated by MAC address filtering could bypass all
    security policies, possibly allowing him to gain access to restricted
    services.
  
Workaround

    Set "MACLIST_TTL" to "0" and "MACLIST_DISPOSITION" to "REJECT" in
    the Shorewall configuration file (usually
    /etc/shorewall/shorewall.conf).
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2317
    http://www.shorewall.net/News.htm#20050717


Solution: 
    All Shorewall users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-firewall/shorewall
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-20] Shorewall: Security policy bypass");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Shorewall: Security policy bypass');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-firewall/shorewall", unaffected: make_list("rge 2.2.5", "ge 2.4.1"), vulnerable: make_list("lt 2.4.1")
)) { security_warning(0); exit(0); }
