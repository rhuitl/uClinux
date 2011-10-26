#
# This script was written by Michel Arboi <mikhail@nessus.org>
# GNU Public Licence
# 
# This is not really a security check.
# See STD0013
#
# Javier Fernandez-Sanguino mentionned 
# http://support.microsoft.com/?id=263237
# XCON: Windows 2000 and Exchange 2000 SMTP Use TCP DNS Queries

if(description)
{
 script_id(18356);
 
 script_version ("$Revision: 1.4 $");
 name["english"] = "DNS Server on UDP and TCP";
 script_name(english:name["english"]);
 
 desc["english"] = "
A DNS server is running on this port but it only 
answers to UDP requests.
This means that TCP requests are blocked by a firewall.

This configuration is not RFC-compliant. Contrary to 
common belief, TCP transport is not restricted to zone 
transfers (AXFR) :
- answers bigger than 512 bytes are always transmitted 
over TCP.
- for all other requests, UDP is only 'preferred' for 
performance reasons. i.e. RFC1035 (STD0013) does not forbid 
a DNS client from issuing its queries directly over TCP.

** If you are sure that your DNS server will never return 
** answers bigger than 512 bytes and that the client 
** software prefers UDP (which is nearly certain), you may 
** disregard this message.

Read RFC1035 (STD0013) for more information.

Risk factor : None";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if the remote DNS servers answers on TCP too";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);

 script_dependencies('external_svc_ident.nasl', 'dns_server.nasl');
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 family["english"] = "General";
 script_family(english:family["english"]);

 exit(0);
}

#

include('global_settings.inc');
include('misc_func.inc');

if (! thorough_tests && report_verbosity > 1)
{
 debug_print('will only run in "Verbose report" or "Thorough tests" mode\n');
 exit(0);
}


port = get_kb_item('Services/udp/dns');
if (! port) exit(0);

if (! get_udp_port_state(port)) exit(0);	# Only on TCP?

if (verify_service(port: port, ipproto: 'tcp', proto: 'dns')) exit(0);

for (try = 0; try < 2; try ++)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    close(soc);
#   if (get_port_state(port))
#     register_service(port: port, proto: 'dns');
    exit(0);
  }
  sleep(1);
}

security_note(port);
