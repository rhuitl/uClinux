# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22920);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-09");
 script_cve_id("CVE-2006-4197");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-09
(libmusicbrainz: Multiple buffer overflows)


    Luigi Auriemma reported a possible buffer overflow in the
    MBHttp::Download function of lib/http.cpp as well as several possible
    buffer overflows in lib/rdfparse.c.
  
Impact

    A remote attacker could be able to execute arbitrary code or cause
    Denial of Service by making use of an overly long "Location" header in
    an HTTP redirect message from a malicious server or a long URL in
    malicious RDF feeds.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4197


Solution: 
    All libmusicbrainz users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/musicbrainz-2.1.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-09] libmusicbrainz: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libmusicbrainz: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/musicbrainz", unaffected: make_list("ge 2.1.4"), vulnerable: make_list("lt 2.1.4")
)) { security_warning(0); exit(0); }
