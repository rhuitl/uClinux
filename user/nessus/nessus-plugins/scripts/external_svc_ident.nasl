# This script was written by Michel Arboi <arboi@alussinan.org>
# It is released under the GNU Public Licence (GPLv2)
#
# We could do this job in amap.nasl or nmap.nasl, but as those
# plugins must be signed to be "trusted", we don't want to change them often

if (description)
{
 script_id(14664);
 script_version("$Revision: 1.11 $");

 desc = "
Synopsis :

This plugin performs service detection.

Description :

This plugin registers services that were identified
by external scanners (amap, nmap, etc...).

It does not perform any fingerprinting by itself.
 
Risk factor : 

None";

 script_description(english: desc);
 script_copyright(english: "(C) 2004 Michel Arboi");
 script_name(english: "external services identification");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Service detection");
 script_summary(english: "Register services that were identified by amap or nmap");
 exit(0);
}

include('misc_func.inc');
include('global_settings.inc');

amapcvt['http'] = 'www';
amapcvt['http-proxy'] = 'http_proxy';
amapcvt['rsyncd'] = 'rsync';
amapcvt['x-windows'] = 'X11';
amapcvt['ms-distribution-transport'] = 'msdtc';

nmapcvt['http'] = 'www';
nmapcvt['http-proxy'] = 'http_proxy';

foreach ipp (make_list('tcp', 'udp'))
{
 ports = get_kb_list('Ports/'+ipp+'/*');
 if (! isnull(ports))
 {
  foreach port  (keys(ports))
  {
   s = get_kb_item('Amap/'+ipp+'/'+port+'/Svc');
   banner = get_kb_item('Amap/'+ipp+'/'+port+'/FullBanner');
   if (!banner)
    banner = get_kb_item('Amap/'+ipp+'/'+port+'/PrintableBanner');
   svc = NULL;

   if (s && s != 'ssl' && s != 'unindentified')
   {
    svc = amapcvt[s];
    if (! svc)
     if (match(string: s, pattern: 'dns-*'))
      svc = 'dns';	# not used yet  
     else if (match(string: s, pattern: 'http-*'))
      svc = 'www';
     else if (match(string: s, pattern: 'nntp-*'))
      svc = 'nntp';
     else if (match(string: s, pattern: 'ssh-*'))
      svc = 'ssh';
     else
      svc = s;
     # Now let's check some suspicious services
     if (s == 'echo' && ipp == 'tcp')
     {
       soc = open_sock_tcp(port);
       if (! soc)
         svc = NULL;
       else
       {
         str = rand_str() + '\n';
         send(socket: soc, data: str);
         b = recv(socket: soc, length: 1024);
         if (b != str) svc = NULL;
         close(soc);
       }
     }
   }
   else
   {
    s = get_kb_item('NmapSvc/'+ipp+'/'+port);
    if ( s ) 
    {
     svc = amapcvt[s];
     if (! svc)	# we probably need some processing...
      svc = s;
    }
   }
   if (svc)
    register_service(port: port, proto: svc, ipproto: ipp);
   else if (b)
    set_unknown_banner(port: port, banner: b, ipproto: ipp);
  }
 }
}

