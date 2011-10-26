#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref:
#  Date: Wed, 9 Jun 2004 15:00:04 +0200
#  From: Stefan Esser <s.esser@e-matters.de>
#  To: full-disclosure@lists.netsys.com, bugtraq@securityfocus.com,
#        red@heisec.de, news@golem.de
#  Subject: Advisory 09/2004: More CVS remote vulnerabilities
#
# This script is released under the GNU GPL v2

if(description)
{
 script_id(12265);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(10499);
 script_cve_id("CVE-2004-0414");
 script_cve_id("CVE-2004-0416");
 script_cve_id("CVE-2004-0417"); 
 script_cve_id("CVE-2004-0418"); 
 script_cve_id("CVE-2004-1471"); 
 if ( defined_func("script_xref") ) script_xref(name:"RHSA", value:"RHSA-2004:233-017");
 
 name["english"] = "CVS malformed entry lines flaw";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote CVS server is affected by multiple issues.

Description :

The remote CVS server, according to its version number, might allow an
attacker to execute arbitrary commands on the remote system because of
a flaw relating to malformed Entry lines which lead to a missing NULL
terminator. 

Among the issues deemed likely to be exploitable were:

- a double-free relating to the error_prog_name string (CVE-2004-0416)
- an argument integer overflow (CVE-2004-0417)
- out-of-bounds writes in serv_notify (CVE-2004-0418)

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2004-June/022441.html

Solution : 

Upgrade to CVS 1.12.9 or 1.11.17

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server and asks the version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service.nes", "cvs_pserver_heap_overflow.nasl");
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);
version =  get_kb_item(string("cvs/", port, "/version"));
if ( ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-6])|12\.[0-8][^0-9]).*", string:version))
     	security_warning(port);
