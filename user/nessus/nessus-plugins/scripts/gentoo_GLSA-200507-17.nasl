# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19222);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-17
(Mozilla Thunderbird: Multiple vulnerabilities)


    The following vulnerabilities were found and fixed in Mozilla
    Thunderbird:
    "moz_bug_r_a4" and "shutdown" discovered
    that Thunderbird was improperly cloning base objects (MFSA
    2005-56).
    "moz_bug_r_a4" also reported that Thunderbird was
    overly trusting contents, allowing privilege escalation via property
    overrides (MFSA 2005-41, 2005-44), that it failed to validate XHTML DOM
    nodes properly (MFSA 2005-55), and that XBL scripts ran even when
    Javascript is disabled (MFSA 2005-46).
    "shutdown" discovered a
    possibly exploitable crash in InstallVersion.compareTo (MFSA
    2005-50).
    Andreas Sandblad from Secunia reported that a child
    frame can call top.focus() even if the framing page comes from a
    different origin and has overridden the focus() routine (MFSA
    2005-52).
    Georgi Guninski reported missing Install object
    instance checks in the native implementations of XPInstall-related
    JavaScript objects (MFSA 2005-40).
    Finally, Vladimir V.
    Perepelitsa discovered a memory disclosure bug in JavaScript\'s regular
    expression string replacement when using an anonymous function as the
    replacement argument (CVE-2005-0989 and MFSA 2005-33).
  
Impact

    A remote attacker could craft malicious email messages that would
    leverage these issues to inject and execute arbitrary script code with
    elevated privileges or help in stealing information.
  
Workaround

    There are no known workarounds for all the issues at this time.
  
References:
    http://www.mozilla.org/projects/security/known-vulnerabilities.html#Thunderbird
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0989


Solution: 
    All Mozilla Thunderbird users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-1.0.5"
    All Mozilla Thunderbird binary users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-1.0.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-17] Mozilla Thunderbird: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Thunderbird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.0.5"), vulnerable: make_list("lt 1.0.5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.0.5"), vulnerable: make_list("lt 1.0.5")
)) { security_warning(0); exit(0); }
