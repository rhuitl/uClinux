# -*- Fundamental -*-
#
# (C) 2002 Michel Arboi <arboi@alussinan.org>
# $Revision: 1.8 $

# test if address is on a LAN, reserved or not routable address

# This disturbs nasl -L, unfortunately
# if (! GLOBAL_SETTINGS_INC) include('global_settings.inc');
 
function is_private_addr(addr)
{
  if (all_addr_private) return 1;
  if (all_addr_public) return 1;

  local_var	a;
  if (! addr)
    a = get_host_ip();
  else
    a = addr;
  # Localhost + RFC1918
  if (a =~ "^0*(127|10)\.[0-9]+\.[0-9]+\.[0-9]+") return 1;
  # RFC 1918 + Link local (RFC 3330)
  if (a =~ "^0*(192\.0*168|169\.0*254)\.[0-9]+\.[0-9]+") return 1;
  # RFC 1918
  if (a =~ "^0*172\.0*(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+") return 1;
  # TEST-NET - RFC 3330
  if (a =~ "^0*192\.0*0\.0*2\.[0-9]+") return 1;
  # RFC 2544
  if (a =~ "^0*192\.0*1[89]\.[0-9]+\.[0-9]+") return 1;
  return 0;
}

#

function test_udp_port(port, data, retries)
{
  local_var	ip, udp, srcaddr, dstaddr, r, f, i, n;

  if (retries <= 0) n = 6; else n = retries;
  if (isnull(data)) data = "";
  for (i = 0; i < n; i ++)
  {
    srcaddr = this_host();
    dstaddr = get_host_ip();
    srcport = 1024 + rand() % 64512;

    ip = forge_ip_packet(ip_v : 4, ip_hl : 5, ip_tos : 0,
                       ip_len : 20, ip_id : 0,
                       ip_p : IPPROTO_UDP, ip_ttl : 255, ip_off : 0,
                       ip_src : srcaddr, ip_dst : dstaddr);

    udp = forge_udp_packet(ip: ip, uh_sport : srcport, uh_dport : port, 
			uh_ulen: 8 + strlen(data), data : data);

    f = strcat("src host ", dstaddr, " and dst host ", srcaddr,
	" and ( (udp and src port ", port, " and dst port ", srcport, ") or (",
	" icmp and icmp[0] = 3 and icmp[1] = 3))");
    r = send_packet(udp, pcap_timeout:1, pcap_active: TRUE, pcap_filter: f);
    if (r)
      if (ord(r[9]) == 17)	# udp
        return 2;
      else
      {
        ##dump(ddata: r, dtitle: "sniffed");
	len = (ord(r[0]) & 0xF); len *= 4;
	icmp = substr(r, len);
        ##dump(ddata: icmp, dtitle: "icmp");
        ip = substr(icmp, 8);	# Original datagram
        ##dump(ddata: ip, dtitle: "ip");
        len = (ord(ip[0]) & 0xF); len *= 4;
        udp = substr(ip, len);
        sp = ord(udp[0])*256 + ord(udp[1]);
	dp = ord(udp[2])*256 + ord(udp[3]);
        if (srcport == sp && port == dp)
          return 0;
      }
  }
  return 1;
}


function ip_checksum(data)
{
  local_var	sum, i, n;
  n = strlen(data);
  sum = 0;
  for (i = 0; i < n - 1; i += 2)
  {
    sum = sum + ord(data[i]) * 256 + ord(data[i+1]);
  }
  if (i < n)
    sum += ord(data[i]);
  sum = (sum >>> 16) + (sum & 0xffff);
  sum += (sum >>> 16);
  sum = (~sum) & 0xFFFF;
  return raw_string(sum % 256, sum / 256);
}

function ms_since_midnight()
{
  local_var	v, s, u;

  if (defined_func("gettimeodday"))
  {
    v = gettimeofday();
    s = v[0]; u = v[1];
    s %= 1000;
    u /= 1000;
    return u + 1000 * s;
  }

  if (defined_func("unixtime"))
  {
    s = unixtime();
    s %= 1000;
    return s * 1000;
  }

  return NULL;
}


function htonl(n)
{
  local_var	i, j, s;

  j = n;	# We do not want to modify a global variable, just in case.
  for (i = 0; i < 4; i ++)
  {
    s[i] = j & 0xFF;
    j >>>= 8;
  }
  return raw_string(s[3], s[2], s[1], s[0]);
}

function htons(n)
{
  return raw_string((n >>> 8) & 0xFF, n & 0xFF);
}

function ntohl(n)
{
 if (strlen(n) != 4)
 {
  display('ntohl: invalid parameter\n');
  return;
 }
 return (ord(n[0]) << 24) | (ord(n[1]) << 16) | (ord(n[2]) << 8) | ord(n[3]);
}
