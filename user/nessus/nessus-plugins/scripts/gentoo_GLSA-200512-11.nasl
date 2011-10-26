# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20352);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-11");
 script_cve_id("CVE-2005-3694", "CVE-2005-3863");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-11
(CenterICQ: Multiple vulnerabilities)


    Gentoo developer Wernfried Haas discovered that when the "Enable
    peer-to-peer communications" option is enabled, CenterICQ opens a port
    that insufficiently validates whatever is sent to it. Furthermore,
    Zone-H Research reported a buffer overflow in the ktools library.
  
Impact

    A remote attacker could cause a crash of CenterICQ by sending
    packets to the peer-to-peer communications port, and potentially cause
    the execution of arbitrary code by enticing a CenterICQ user to edit
    overly long contact details.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3694
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3863
    http://www.zone-h.org/en/advisories/read/id=8480/


Solution: 
    All CenterICQ users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/centericq-4.21.0-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-11] CenterICQ: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CenterICQ: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/centericq", unaffected: make_list("ge 4.21.0-r2"), vulnerable: make_list("lt 4.21.0-r2")
)) { security_warning(0); exit(0); }
