# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20236);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-15");
 script_cve_id("CVE-2005-2851");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-15
(Smb4k: Local unauthorized file access)


    A vulnerability leading to unauthorized file access has been
    found. A pre-existing symlink from /tmp/sudoers and /tmp/super.tab to a
    textfile will cause Smb4k to write the contents of these files to the
    target of the symlink, as Smb4k does not check for the existence of
    these files before writing to them.
  
Impact

    An attacker could acquire local privilege escalation by adding
    username(s) to the list of sudoers.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2851
    http://smb4k.berlios.de/


Solution: 
    All smb4k users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/smb4k-0.6.4"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-15] Smb4k: Local unauthorized file access");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Smb4k: Local unauthorized file access');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/smb4k", unaffected: make_list("ge 0.6.4"), vulnerable: make_list("lt 0.6.4")
)) { security_hole(0); exit(0); }
