# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20261);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-17");
 script_cve_id("CVE-2005-3531");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-17
(FUSE: mtab corruption through fusermount)


    Thomas Biege discovered that fusermount fails to securely handle
    special characters specified in mount points.
  
Impact

    A local attacker could corrupt the contents of the /etc/mtab file
    by mounting over a maliciously-named directory using fusermount,
    potentially allowing the attacker to set unauthorized mount options.
    This is possible only if fusermount is installed setuid root, which is
    the default in Gentoo.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3531


Solution: 
    All FUSE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-fs/fuse-2.4.1-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-17] FUSE: mtab corruption through fusermount");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FUSE: mtab corruption through fusermount');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-fs/fuse", unaffected: make_list("ge 2.4.1-r1"), vulnerable: make_list("lt 2.4.1-r1")
)) { security_warning(0); exit(0); }
