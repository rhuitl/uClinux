#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10423);
 script_bugtraq_id(1133);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0320");
 
 name["english"] = "qpopper euidl problem";
 name["francais"] = "qpopper euild";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
Synopsis :

It is possible to execute arbitrary code on the remote host
through the remote POP server

Description :


The remote version of the qpopper POP server contains a bug
which may allow authenticated users who have a pop account 
to gain a shell with the gid 'mail' by sending to themselves a 
specially crafted mail.


Solution : 

Upgrade to the latest qpopper software

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "checks for the version of qpopper";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
		       		     
 script_require_ports("Services/pop3", 110);
 exit(0);
}

include("pop3_func.inc");
port = get_kb_item("Services/pop3");
if(!port)port = 110;


banner = get_pop3_banner(port:port);
if ( ! banner ) exit(0);

if(ereg(pattern:"^\+OK QPOP \(version (2\.((5[3-9]+)|([6-9][0-9]+))\)|3\.0).*$", string:banner)) security_warning(port);
	  

