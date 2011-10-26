#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
# See the Nessus Scripts License for details
#
#
# Improved by John Lampe to see if XEXCH is an allowed verb

if(description)
{
     script_id(11889);
     script_bugtraq_id(8838);
     if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0031");
     if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-a-0016");
     script_cve_id("CVE-2003-0714");
     script_version("$Revision: 1.11 $");
     name["english"] = "Exchange XEXCH50 Remote Buffer Overflow";
     script_name(english:name["english"]);

     desc["english"] = 
"This system appears to be running a version of the Microsoft Exchange
SMTP service that is vulnerable to a flaw in the XEXCH50 extended verb.
This flaw can be used to completely crash Exchange 5.5 as well as execute
arbitrary code on Exchange 2000. 

Solution : See http://www.microsoft.com/technet/security/bulletin/MS03-046.mspx
Risk factor : High";

    script_description(english:desc["english"]);
		    
 
    summary["english"] = "Tests to see if authentication is required for the XEXCH50 command";
    script_summary(english:summary["english"]);
 		 
 
    script_category(ACT_GATHER_INFO);
 
    script_copyright(english:"This script is Copyright (C) 2003 Digital Defense Inc.");
 
    family["english"] = "SMTP problems";
    family["francais"] = "Problèmes SMTP";
    script_family(english:family["english"], francais:family["francais"]);
    
    script_dependencies("smtpserver_detect.nasl");
    script_exclude_keys("SMTP/wrapped");
    script_require_ports("Services/smtp", 25);
    exit(0);
}

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);


greeting = smtp_recv_banner(socket:soc);
if(debug) display("GREETING: ", greeting, "\n");

# look for the exchange banner, removing this may get us through some proxies
if (! egrep(string:greeting, pattern:"microsoft", icase:TRUE)) exit(0);

send(socket:soc, data:string("EHLO X\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug) display("HELO: ", ok, "\n");
if("XEXCH50" >!< ok)exit(0);

send(socket:soc, data:string("MAIL FROM: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug) display("MAIL: ", ok, "\n");

send(socket:soc, data:string("RCPT TO: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug) display("RCPT: ", ok, "\n");

send(socket:soc, data:string("XEXCH50 2 2\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug) display("XEXCH50: ", ok, "\n");

if (egrep(string:ok, pattern:"^354 Send binary")) security_hole(port:port);

close(soc);
