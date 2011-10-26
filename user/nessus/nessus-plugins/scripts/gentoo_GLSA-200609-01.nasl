# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22323);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-01");
 script_cve_id("CVE-2006-3124");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-01
(Streamripper: Multiple remote buffer overflows)


    Ulf Harnhammar, from the Debian Security Audit Project, has found that
    Streamripper is vulnerable to multiple stack based buffer overflows
    caused by improper bounds checking when processing malformed HTTP
    headers.
  
Impact

    By enticing a user to connect to a malicious server, an attacker could
    execute arbitrary code with the permissions of the user running
    Streamripper
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3124


Solution: 
    All Streamripper users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-sound/streamripper-1.61.26"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-01] Streamripper: Multiple remote buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Streamripper: Multiple remote buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/streamripper", unaffected: make_list("ge 1.61.26"), vulnerable: make_list("lt 1.61.26")
)) { security_warning(0); exit(0); }
