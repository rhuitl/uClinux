#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11570);
 script_bugtraq_id(6053);
 script_cve_id("CVE-2002-1539");
 script_version ("$Revision: 1.4 $");
 
 
 name["english"] = "MDaemon DELE DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to crash the remote MDaemon server by suppling 
oversized arguments to the commands DELE and UIDL.

An attacker may use this flaw to prevent other users from
fetching their e-mail. It will also crash other MDaemon services
(SMTP, IMAP), thus preventing this server from receiving any email
as well.

To exploit this flaw, a valid POP account is needed.

*** Nessus solely relied on the version number of the remote server
*** to issue this warning.

Solution : upgrade to MDaemon 6.5.0
Risk factor : High";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines the version number of the remote POP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sendmail_expn.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#


include("pop3_func.inc");
port = get_kb_item("Services/pop3");
if(!port)port = 110;
banner  = get_pop3_banner( port : port );
if ( ! banner ) exit(0);
if(ereg(pattern:"POP MDaemon ([0-5]\.|6\.[0-4]\.)", string:banner))
 	security_hole(port);
