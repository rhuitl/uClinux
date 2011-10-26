# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22284);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-22");
 script_cve_id("CVE-2006-3119");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-22
(fbida: Arbitrary command execution)


    Toth Andras has discovered a typographic mistake in the "fbgs" script,
    shipped with fbida if the "fbcon" and "pdf" USE flags are both enabled.
    This script runs "gs" without the -dSAFER option, thus allowing a
    PostScript file to execute, delete or create any kind of file on the
    system.
  
Impact

    A remote attacker can entice a vulnerable user to view a malicious
    PostScript or PDF file with fbgs, which may result with the execution
    of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3119


Solution: 
    All fbida users with the "fbcon" and "pdf" USE flags both enabled
    should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/fbida-2.03-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-22] fbida: Arbitrary command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'fbida: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/fbida", unaffected: make_list("ge 2.03-r4"), vulnerable: make_list("lt 2.03-r4")
)) { security_warning(0); exit(0); }
