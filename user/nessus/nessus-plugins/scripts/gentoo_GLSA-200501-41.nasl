# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-41.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16432);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200501-41");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-41
(TikiWiki: Arbitrary command execution)


    TikiWiki does not validate files uploaded to the "temp" directory.
  
Impact

    A malicious user could run arbitrary commands on the server by
    uploading and calling a PHP script.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://tikiwiki.org/art102


Solution: 
    All TikiWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/tikiwiki-1.8.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-41] TikiWiki: Arbitrary command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TikiWiki: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.8.5"), vulnerable: make_list("lt 1.8.5")
)) { security_hole(0); exit(0); }
