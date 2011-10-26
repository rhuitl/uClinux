#
# This script was written by Michel Arboi <mikhail@nessus.org>
#
# It is released under the GNU Public Licence (GPLv2)
#
# References:
# RFC 1788
# http://www.dolda2000.com/~fredrik/icmp-dn/
#

desc = "
Synopsis :

The remote host answers to ICMP 'domain name' messages.

Description :

The remote host answered to an ICMP 'Domain Name Request'
as defined in RFC 1788.

Such a request is designed to obtain the DNS name of a host 
based on its IP. 

See also :

http://www.ietf.org/rfc/rfc1788.txt

Solution :

If you do not use this feature, filter out incoming ICMP packets 
of type 37 and outgoing ICMP packets of type 38.

Risk factor :

None
";

if(description)
{
 script_id(20887);
 script_version ("$Revision: 1.2 $");
 script_name(english: "ICMP domain name request");
 
 script_description(english: desc);
 
 script_summary(english: "Sends an ICMP Domain Name request");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
 family["english"] = "General";
 family["francais"] = "General";
 script_family(english:family["english"], francais:family["francais"]);
 exit(0);
}



include('global_settings.inc');

if ( thorough_tests ) max = 3;
else max = 1;


# 00: 09 63 61 73 73 65 72 6f 6c 65 06 28 6e 6f 6e 65    .casserole.(none
# 10: 29 00                                              ).

function extract_dns_data(dns)
{
 local_var v, vi, l, i, s, n, i1, n1, out;

 v = NULL; vi = 0;
 l = strlen(dns);
 i = 0;
 while (i < l)
 {
  s = '';
  while (i < l)
  {
   n = ord(dns[i ++]);
   if (n == 0) break;
   if ((n & 0xC0) == 0xC0)	# DNS compression
   {
    i1 = (n & 0x3F) << 8 | ord(dns[i++]);
    n1 = ord(dns[i1 ++]);
    if ( i1 + n1 >= l ) break; # Invalid offset
    if (n1 & 0xC0 == 0xC0) display('icmp_domain_name.nasl: ', get_host_ip(), ' returned a packet with chained DNS compression\n');
    else 
     s = strcat(s, substr(dns, i1, i1+n1-1), '.');
   }
   else
    {
    if ( i + n > l ) break;
    s = strcat(s, substr(dns, i, i+n-1), '.');
    }
   i += n;
  }
  v[vi++] = s;
 }

 out = '';
 for (i = 0; i < vi; i ++) { out = strcat(out, v[i], '\n'); }
 return out;
}


if (islocalhost()) exit(0);

ip = forge_ip_packet(ip_hl:5, ip_v:4, ip_off:0,
                     ip_tos:0, ip_p : IPPROTO_ICMP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

icmp = forge_icmp_packet(ip:ip,icmp_type: 37, icmp_code:0,
                          icmp_seq : 1, icmp_id : 1);

filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host(), " and icmp[0] = 38");

for(i = 0; i < max; i ++)
{
 r = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
 if(!isnull(r))
 {
  type = get_icmp_element(icmp:r, element:"icmp_type");
  if(type == 38)
  {
   hl = (ord(r[0]) & 0x0F) * 4;
   data = substr(r, hl + 12);
   # dump(ddata: data, dtitle: "DATA");
   output = extract_dns_data(dns: data);
   if (output)
    security_warning(protocol:"icmp", port:0, data: desc + '\nPlugin output :\n\n' + output);
   else
    security_warning(protocol:"icmp", port:0);
   set_kb_item(name: 'icmp/domain_name', value: TRUE);
  }
  # display("type=", type, "\n");
  exit(0);
 }
}

