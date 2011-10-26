# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18252);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200505-09");
 script_cve_id("CVE-2005-1261", "CVE-2005-1262");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-09
(Gaim: Denial of Service and buffer overflow vulnerabilties)


    Stu Tomlinson discovered that Gaim is vulnerable to a remote stack
    based buffer overflow when receiving messages in certain protocols,
    like Jabber and SILC, with a very long URL (CVE-2005-1261). Siebe
    Tolsma discovered that Gaim is also vulnerable to a remote Denial of
    Service attack when receiving a specially crafted MSN message
    (CVE-2005-1262).
  
Impact

    A remote attacker could cause a buffer overflow by sending an
    instant message with a very long URL, potentially leading to the
    execution of malicious code. By sending a SLP message with an empty
    body, a remote attacker could cause a Denial of Service or crash of the
    Gaim client.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1261
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1262


Solution: 
    All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gaim-1.3.0"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-09] Gaim: Denial of Service and buffer overflow vulnerabilties");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Denial of Service and buffer overflow vulnerabilties');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.3.0"), vulnerable: make_list("lt 1.3.0")
)) { security_hole(0); exit(0); }
