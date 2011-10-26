# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22119);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200607-11");
 script_cve_id("CVE-2006-3600");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200607-11
(TunePimp: Buffer overflow)


    Kevin Kofler has reported a vulnerability where three stack variables
    are allocated with 255, 255 and 100 bytes respectively, yet 256 bytes
    are read into each. This could lead to buffer overflows.
  
Impact

    Running an affected version of TunePimp could lead to the execution of
    arbitrary code by a remote attacker.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3600
    http://bugs.musicbrainz.org/ticket/1764


Solution: 
    TunePimp has been masked in Portage pending the resolution of these
    issues. TunePimp users are advised to uninstall the package until
    further notice:
    # emerge --ask --unmerge "media-libs/tunepimp"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200607-11] TunePimp: Buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TunePimp: Buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/tunepimp", unaffected: make_list(), vulnerable: make_list("le 0.4.2")
)) { security_warning(0); exit(0); }
