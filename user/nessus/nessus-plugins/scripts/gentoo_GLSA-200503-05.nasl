# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17261);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-05");
 script_cve_id("CVE-2001-0775");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-05
(xli, xloadimage: Multiple vulnerabilities)


    Tavis Ormandy of the Gentoo Linux Security Audit Team has reported
    that xli and xloadimage contain a flaw in the handling of compressed
    images, where shell meta-characters are not adequately escaped. Rob
    Holland of the Gentoo Linux Security Audit Team has reported that an
    xloadimage vulnerability in the handling of Faces Project images
    discovered by zen-parse in 2001 remained unpatched in xli.
    Additionally, it has been reported that insufficient validation of
    image properties in xli could potentially result in buffer management
    errors.
  
Impact

    Successful exploitation would permit a remote attacker to execute
    arbitrary shell commands, or arbitrary code with the privileges of the
    xloadimage or xli user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0775


Solution: 
    All xli users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xli-1.17.0-r1"
    All xloadimage users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xloadimage-4.1-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-05] xli, xloadimage: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xli, xloadimage: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/xloadimage", unaffected: make_list("ge 4.1-r2"), vulnerable: make_list("lt 4.1-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-gfx/xli", unaffected: make_list("ge 1.17.0-r1"), vulnerable: make_list("lt 1.17.0-r1")
)) { security_warning(0); exit(0); }
