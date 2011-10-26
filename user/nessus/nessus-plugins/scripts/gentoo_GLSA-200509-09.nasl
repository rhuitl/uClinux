# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19741);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-09");
 script_cve_id("CVE-2005-2875");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-09
(Py2Play: Remote execution of arbitrary Python code)


    Arc Riley discovered that Py2Play uses Python pickles to send
    objects over a peer-to-peer game network, and that clients accept
    without restriction the objects and code sent by peers.
  
Impact

    A remote attacker participating in a Py2Play-powered game can send
    malicious Python pickles, resulting in the execution of arbitrary
    Python code on the targeted game client.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2875


Solution: 
    The Py2Play package has been hard-masked prior to complete removal
    from Portage, and current users are advised to unmerge the package:
    # emerge --unmerge  dev-python/py2play
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-09] Py2Play: Remote execution of arbitrary Python code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Py2Play: Remote execution of arbitrary Python code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-python/py2play", unaffected: make_list(), vulnerable: make_list("le 0.1.7")
)) { security_hole(0); exit(0); }
