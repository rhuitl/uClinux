# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20266);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-22");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-22
(Inkscape: Buffer overflow)


    Joxean Koret has discovered that Inkscape incorrectly allocates
    memory when opening an SVG file, creating the possibility of a buffer
    overflow if the SVG file being opened is specially crafted.
  
Impact

    An attacker could entice a user into opening a maliciously crafted
    SVG file, allowing for the execution of arbitrary code on a machine
    with the privileges of the user running Inkscape.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3737


Solution: 
    All Inkscape users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/inkscape-0.43"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-22] Inkscape: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Inkscape: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/inkscape", unaffected: make_list("ge 0.43"), vulnerable: make_list("lt 0.43")
)) { security_warning(0); exit(0); }
