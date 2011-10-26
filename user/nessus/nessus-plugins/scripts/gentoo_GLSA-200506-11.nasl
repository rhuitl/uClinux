# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18468);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200506-11");
 script_cve_id("CVE-2005-1269", "CVE-2005-1934");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-11
(Gaim: Denial of Service vulnerabilities)


    Jacopo Ottaviani discovered a vulnerability in the Yahoo! file
    transfer code when being offered files with names containing non-ASCII
    characters (CVE-2005-1269).
    Hugo de Bokkenrijder discovered a
    vulnerability when receiving malformed MSN messages (CVE-2005-1934).
  
Impact

    Both vulnerabilities cause Gaim to crash, resulting in a Denial of
    Service.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://gaim.sourceforge.net/security/?id=18
    http://gaim.sourceforge.net/security/?id=19
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1269
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1934


Solution: 
    All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gaim-1.3.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-11] Gaim: Denial of Service vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.3.1"), vulnerable: make_list("lt 1.3.1")
)) { security_warning(0); exit(0); }
