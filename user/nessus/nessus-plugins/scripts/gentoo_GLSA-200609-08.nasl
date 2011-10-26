# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22353);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-08");
 script_cve_id("CVE-2006-2802");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-08
(xine-lib: Buffer overflows)


    xine-lib contains buffer overflows in the processing of AVI.
    Additionally, xine-lib is vulnerable to a buffer overflow in the HTTP
    plugin (xineplug_inp_http.so) via a long reply from an HTTP server.
  
Impact

    An attacker could trigger the buffer overflow vulnerabilities by
    enticing a user to load a specially crafted AVI file in xine. This
    might result in the execution of arbitrary code with the rights of the
    user running xine. Additionally, a remote HTTP server serving a xine
    client a specially crafted reply could crash xine and possibly execute
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2802


Solution: 
    All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/xine-lib-1.1.2-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-08] xine-lib: Buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: Buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1.1.2-r2"), vulnerable: make_list("lt 1.1.2-r2")
)) { security_warning(0); exit(0); }
