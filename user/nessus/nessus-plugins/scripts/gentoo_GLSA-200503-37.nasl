# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-37.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17667);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-37");
 script_cve_id("CVE-2005-0788", "CVE-2005-0789");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-37
(LimeWire: Disclosure of sensitive information)


    Two input validation errors were found in the handling of Gnutella
    GET requests (CVE-2005-0788) and magnet requests (CVE-2005-0789).
  
Impact

    A remote attacker can craft a specific Gnutella GET request or use
    directory traversal on magnet requests to read arbitrary files on the
    system with the rights of the user running LimeWire.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0788
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0789
    http://secunia.com/advisories/14555/


Solution: 
    All LimeWire users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-p2p/limewire-4.8.1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-37] LimeWire: Disclosure of sensitive information");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LimeWire: Disclosure of sensitive information');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-p2p/limewire", unaffected: make_list("ge 4.8.1"), vulnerable: make_list("lt 4.8.1")
)) { security_warning(0); exit(0); }
