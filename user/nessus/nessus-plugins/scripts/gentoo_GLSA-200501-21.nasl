# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16412);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-21");
 script_cve_id("CVE-2004-1182");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-21
(HylaFAX: hfaxd unauthorized login vulnerability)


    The code used by hfaxd to match a given username and hostname with
    an entry in the hosts.hfaxd file is insufficiently protected against
    malicious entries.
  
Impact

    If the HylaFAX installation uses a weak hosts.hfaxd file, a remote
    attacker could authenticate using a malicious username or hostname and
    bypass the intended access restrictions.
  
Workaround

    As a workaround, administrators may consider adding passwords to
    all entries in the hosts.hfaxd file.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1182
    http://marc.theaimsgroup.com/?l=hylafax&m=110545119911558&w=2


Solution: 
    All HylaFAX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/hylafax-4.2.0-r2"
    Note: Due to heightened security, weak entries in the
    hosts.hfaxd file may no longer work. Please see the HylaFAX
    documentation for details of accepted syntax in the hosts.hfaxd file.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-21] HylaFAX: hfaxd unauthorized login vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'HylaFAX: hfaxd unauthorized login vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/hylafax", unaffected: make_list("ge 4.2.0-r2"), vulnerable: make_list("lt 4.2.0-r2")
)) { security_warning(0); exit(0); }
