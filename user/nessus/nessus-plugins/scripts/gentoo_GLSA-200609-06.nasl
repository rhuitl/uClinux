# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22351);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-06");
 script_cve_id("CVE-2006-3581", "CVE-2006-3582");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-06
(AdPlug: Multiple vulnerabilities)


    AdPlug is vulnerable to buffer and heap overflows when processing the
    following types of files: CFF, MTK, DMO, U6M, DTM, and S3M.
  
Impact

    By enticing a user to load a specially crafted file, an attacker could
    execute arbitrary code with the privileges of the user running AdPlug.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.securityfocus.com/archive/1/439432/30/0/threaded
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3581
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3582


Solution: 
    All AdPlug users should update to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/adplug-2.0.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-06] AdPlug: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AdPlug: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/adplug", unaffected: make_list("ge 2.0.1"), vulnerable: make_list("lt 2.0.1")
)) { security_warning(0); exit(0); }
