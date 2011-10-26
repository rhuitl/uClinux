# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19388);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200508-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-04
(Netpbm: Arbitrary code execution in pstopnm)


    Max Vozeler reported that pstopnm calls the GhostScript
    interpreter on untrusted PostScript files without specifying the
    -dSAFER option, to convert a PostScript file into a PBM, PGM, or PNM
    file.
  
Impact

    An attacker could craft a malicious PostScript file and entice a
    user to run pstopnm on it, resulting in the execution of arbitrary
    commands with the permissions of the user running pstopnm.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/16184/


Solution: 
    All Netpbm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/netpbm-10.28"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-04] Netpbm: Arbitrary code execution in pstopnm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Netpbm: Arbitrary code execution in pstopnm');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/netpbm", unaffected: make_list("ge 10.28"), vulnerable: make_list("lt 10.28")
)) { security_warning(0); exit(0); }
