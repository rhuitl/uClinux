#TRUSTED 5aae6566493bcf2660deedf0f85f8b133518cf5bf3dd04abe744a1b443d86cfae43b047291c7589949cd0c73680e493df676eb4977f1f2c7aba59da3ee926605bd713615c8b47ac1b2f8b2259d19f642a6ea679ca5d0f2a39ef43d539da497b03ead9c291a2fd2f6e6125e1d1889e7712959314f6c8184ea50b078da7effd9893b9bbd93ce892a1cda7031bf42dc8ac58757d506b5e062d43f25ff3e285be0d893d47f7d54fcedfc401a0c0d33d0cf29051a283ee43051bb176d51a43b4635681b47135d0a7dbd1fd08266587d361493c56b4a640b2d0000cbc2d18386fe9e302e5dc5981f837dd9871272be98b4d9cb91c2706638741b9cbb115ee6699db22448ac9634da52325c4555f14eb191cad2822120a0944b3a608895b888948ef5785b23a9caecf3be2dc11aeb0325102324b76ffed2af6621538069f07b7d2e07628fef0055da5222e08223dab5402d8d371983a72451824f6cf1eb7166fada590829b2faefd8a2c11d48318fc21fdd7bd44be275fb64a4d30f3c938443563f21e1e7bb6771997c47db3c8562256c21530118a5cd8fe4b58c8d35f0687f832647a10fcc9a9f3d919020789ba8f3178978f86bb6761c20e917b2d6d8e5f32964f71b86d0fe7789a86e01ab413b333072e5738c58cd873619c428f456adc1b979eed74d4c5e9f51e3ee68c2882c530eca38317bcd7e515dddb670c08cfc84b798fa70
#
#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(12634);
 script_version ("2.2");
 name["english"] = "Enable local security checks";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This scripts logs into the remote host using SSH, RSH, RLOGIN, Telnet
or local commands and extracts the list of installed packages. 
To work properly, this script requires that you configure it with a valid 
SSH public key to use and eventually an SSH passphrase if the SSH public 
key is passphrase-protected or that you run it against localhost.";


 script_description(english:desc["english"]);
 
 summary["english"] = "Obtains the remote OS name and installed packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 
 script_dependencies("find_service.nes", "ssh_settings.nasl", "clrtxt_proto_settings.nasl");
# script_require_ports(22, "Services/ssh", 23, "Services/telnet", 512, 513, 514);
 exit(0);
}


include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

report = "";
info_t = 0;

#### Choose "transport" ####


ssh_failed = 0; 
telnet_failed = 0;
port_g = NULL; 
sock_g = NULL;

if (islocalhost() && defined_func("fread") && defined_func("pread"))
{
 info_t = INFO_LOCAL;
 set_kb_item(name: 'HostLevelChecks/proto', value: 'local');
}

if (! info_t)
{
 if (defined_func("bn_random"))
 {
  port22 = kb_ssh_transport();
  sock_g = ssh_login_or_reuse_connection();
  private_key = kb_ssh_privatekey();
 }
 if (sock_g)
 {
  info_t = INFO_SSH;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'ssh');
  port_g = port22;
 }
 else 
 {
  ssh_failed = 1;
  if ( kb_ssh_login() && ( kb_ssh_password() || kb_ssh_privatekey() )  ) set_kb_item(name: 'HostLevelChecks/ssh/failed', value:TRUE);
  try_telnet = get_kb_item("HostLevelChecks/try_telnet");
  try_rlogin = get_kb_item("HostLevelChecks/try_rlogin");
  try_rsh    = get_kb_item("HostLevelChecks/try_rsh");
  try_rexec  = get_kb_item("HostLevelChecks/try_rexec");
  login      = get_kb_item("Secret/ClearTextAuth/login");
  pass       = get_kb_item("Secret/ClearTextAuth/pass");
 }
}


if (! info_t && try_rlogin && strlen(login) > 0)
{
 port513 = get_kb_item("Services/rlogin");
 if (! port513) port513 = 513;

 sock_g = rlogin(port: port513, login: login, pass: pass);
 if (sock_g)
 {
  info_t = INFO_RLOGIN;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rlogin');
  port_g = port513;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rlogin/failed', value:TRUE);
  rlogin_failed = 1;
  }
}

if (! info_t && try_rsh && strlen(login) > 0 )
{
 port514 = get_kb_item("Services/rsh");
 if (! port514) port514 = 514;
 r = send_rsh(port: port514, cmd: 'id');
 if ("uid=" >< r)
 {
  info_t = INFO_RSH;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rsh');
  port_g = port514;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rsh/failed', value:TRUE);
  rsh_failed = 1;
  }
}

if (! info_t && try_rexec && strlen(login) > 0)
{
 port512 = get_kb_item("Services/rexec");
 if (! port512) port512 = 512;
  r = send_rexec(port: port512, cmd: 'id');
 if ("uid=" >< r)
 {
  info_t = INFO_REXEC;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rexec');
  port_g = port512;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rexec/failed', value:TRUE);
  rexec_failed = 1;
  }
}


if (! info_t && try_telnet && strlen(login) > 0 && strlen(pass) > 0)
{
 port23 = get_kb_item("Services/telnet");
 if (! port23) port23 = 23;
  sock_g = telnet_open_cnx(port: port23, login: login, pass: pass);
 if (sock_g)
 {
  info_t = INFO_TELNET;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'telnet');
  port_g = port23;
 }
 else
 {
  set_kb_item(name: 'HostLevelChecks/telnet/failed', value:TRUE);
  telnet_failed = 1;
 }
}

#

if (info_t == INFO_LOCAL)
 report = "Nessus can run commands on localhost to check if patches are applied";
else if (info_t == INFO_SSH && private_key)
	report = "It was possible to log into the remote host using the supplied asymetric keys"; 
else
	report = "It was possible to log into the remote host using the supplied password"; 

if ( info_t == 0 ) exit(0);


# Determine the remote operating system type

# Windows is not supported
buf = info_send_cmd(cmd: 'cmd /C ver');
if ( buf && ("Microsoft Windows" >< buf)) exit(0);


buf = info_send_cmd(cmd: 'uname -a');

if ( buf ) set_kb_item(name:"Host/uname", value:buf);
else {
	report += 
'\nHowever the execution of the command "uname -a" failed, so local security
checks have not been enabled';

	if (info_t == INFO_SSH)
	{
         error = ssh_cmd_error();
         if (strlen(error) > 0)
          report += '\n\nNessus return the following error message :\n' + error;
	}

	security_note(port:port, data:report);
	exit(0);
     }


report += '\nThe output of "uname -a" is :\n' + buf;


############################# FreeBSD ###########################################
if ( "FreeBSD" >< buf )
{
  release = ereg_replace(pattern:".*FreeBSD ([0-9]\.[^ ]*).*", replace:"\1", string:buf);
 items = split(release, sep:"-", keep:0);
 if ( "p" >< items[2] ) items[2] = ereg_replace(pattern:"p", replace:"_", string:items[2]);
 release = "FreeBSD-" + items[0] + items[2];
 set_kb_item(name:"Host/FreeBSD/release", value:release); 
 buf = info_send_cmd(cmd: "/usr/sbin/pkg_info");

  if ( ! buf )  {
	report += 
'\nThe command "pkg_info" did not return any result, therefore FreeBSD local 
security checks have not been enabled for this test';
	security_note(port:port, data:report);
	set_kb_item(name:'HostLevelChecks/failure', value:"'pkg_info' did not return any result");
	}
  else {
        set_kb_item(name:"Host/FreeBSD/pkg_info", value:buf);
	set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
        report += '\nLocal security checks have been enabled for this host.';
	security_note(port:port, data:report);
	exit(0);
	}
}
######################## RedHat Linux ###########################################
else if ("Linux" >< buf )
{
  buf = info_send_cmd(cmd: "cat /etc/redhat-release");

  if ( egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release ([34]|2\.1)", string:buf) ||
       egrep(pattern:"Fedora Core.*", string:buf) )
  {
   if ( "Red Hat" >< buf ) report += '\nThe remote Red Hat system is :\n' + buf;
   else if ("Fedora" >< buf ) report += '\nThe remote Fedora system is :\n' + buf;
   set_kb_item(name:"Host/RedHat/release", value:buf);
   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");

   if ( ! buf )
   {
     report += 
'\nThe command "rpm -qa" did not produce any result, therefore local security 
checks have been disabled';
    security_note(port:port, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:"Host/RedHat/rpm-list", value:buf);
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:port, data:report);
   exit(0);
  }
 else if ( "CentOS" >< buf )
 {
   set_kb_item(name:"Host/CentOS/release", value:buf);
   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   if ( ! buf )
   {
     report += 
'\nThe command "rpm -qa" did not produce any result, therefore local security 
checks have been disabled';
    security_note(port:port, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }
   set_kb_item(name:"Host/CentOS/rpm-list", value:buf);

   buf = info_send_cmd(cmd:"uname -m");
   if ( ! buf )
   {
     report += 
'\nThe command "uname -m" did not produce any result, therefore local security 
checks have been disabled';
    security_note(port:port, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }

   set_kb_item(name:"Host/cpu", value:buf);
   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:port, data:report);
   exit(0);
 }
#####################   Mandrake ####################################################
#Mandrake Linux release 9.1 (Bamboo) for i586
  else
  {
  #buf = ssh_cmd(socket:sock, cmd:"cat /etc/redhat-release");
  if (("Mandrake Linux" >< buf && "Mandrake Linux Corporate" >!< buf) || "Mandrakelinux" >< buf || 
	"Mandriva Linux release" >< buf )
  {
   report += '\nThe remote Mandrake system is :\n' + buf;
   version = ereg_replace(pattern:"(Mandrake Linux|Mandrakelinux|Mandriva Linux) release ([0-9]+\.[0-9]) .*", string:egrep(string:buf, pattern:"Mandr(ake|iva)"), replace:"\2");
   set_kb_item(name:"Host/Mandrake/release", value:"MDK" + version);
   
   #report += '\ndebug:\n' + version;
   
   buf = info_send_cmd(cmd:"rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");

   if ( ! buf )
   {
     report +=
'\nThe command "rpm -qa" did not produce any result, therefore local security
checks have been disabled';
    security_note(port:port, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:"Host/Mandrake/rpm-list", value:buf);
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:port, data:report);
   exit(0);
  }
  }

###################### SuSE ###############################################################

  buf = info_send_cmd(cmd: "cat /etc/SuSE-release");

# SuSE Linux Enterprise Server says:
# SuSE SLES-8 (i386)
# VERSION = 8.1
# SuSE pro says:
# SuSE Linux 9.3 (i586)
# VERSION = 9.3
# Version 10.0 on Live CD says:
# SUSE LINUX 10.0 (i586)
# VERSION = 10.0

  if (buf && ("suse linux" >< tolower(buf) || "SuSE SLES" >< buf))
  {
    version = '';
    report += '\nThe remote SuSE system is :\n' + egrep(pattern:"^SuSE", string:buf, icase:TRUE);
    version = egrep(string: buf, pattern: "^VERSION *= *[0-9.]+$");
    version = chomp(ereg_replace(pattern: "^VERSION *= *", string: version, replace: ""));
    if (! version)
    {
      v = eregmatch(pattern:"SuSE Linux ([0-9]+\.[0-9]) .*", 
		    string:egrep(string:buf, pattern:"SuSE ", icase:1), 
                    icase:TRUE);
      if (! isnull(v)) version = v[1];
    }
    if (! version)
    {
      report += '\nThis version of SuSE Linux could not be precisely identified,\ntherefore local securityhave been disabled';
      security_note(port:port, data:report);
      set_kb_item(name:'HostLevelChecks/failure', value:"Could not identify the version of the remote SuSE system");
      exit(0);
    }

	set_kb_item(name:"Host/SuSE/release", value:"SUSE" + version);
	buf = info_send_cmd(cmd:"rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");

   if ( ! buf )
   {
     report += 
'\nThe command "rpm -qa" did not produce any result, therefore local security 
checks have been disabled';
    security_note(port:port, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:"Host/SuSE/rpm-list", value:buf);
   set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
   security_note(port:port, data:report);
   exit(0);
  }
  
###################### Gentoo ###############################################

  buf = info_send_cmd(cmd: "cat /etc/gentoo-release");

  if ( buf && "Gentoo" >< buf )
  {
    if ( "Gentoo" >< buf )
      report += '\nThe remote Gentoo system is :\n' + egrep(pattern:"^Gentoo", string:buf);
    version = ereg_replace(pattern:"Gentoo Base System version (([0-9]+\.)*[0-9]+).*",
                             string:egrep(string:buf, pattern:"Gentoo"), replace:"\1");
    # Release does not make much sense on Gentoo
    set_kb_item(name:"Host/Gentoo/release", value: version);

    buf = info_send_cmd(cmd: 'egrep "ARCH=" /etc/make.profile/make.defaults');

    buf = ereg_replace(string: buf, pattern: 'ARCH="(.*)"', replace: "\1");
    set_kb_item(name: "Host/Gentoo/arch", value: buf);

    # A great idea from David Maciejak: 
    # 1. app-portage/gentoolkit is not necessarily installed 
    # 2. and this find is quicker than "qpkg -v -I -nc"
    buf = info_send_cmd(cmd:'find /var/db/pkg/ -mindepth 2 -maxdepth 2 -printf "%P\\n"');
    if (buf)
    {
      report += '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/Gentoo/qpkg-list", value:buf);
      set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
      security_note(port:port, data:report);
    }
    else
    {
      report += 
'For any reason, find did not produce any result, therefore local security 
checks have been disabled';
     set_kb_item(name:'HostLevelChecks/failure', value:"'find /var/db/pkg/' did not return any result");
     security_note(port:port, data:report);
    }
    exit(0);
    }

###################### Debian ###############################################
  buf = info_send_cmd(cmd: "cat /etc/debian_version");

  if ( buf && egrep(string:buf, pattern:'^([0-9.]+|testing/unstable)[ \t\r\n]*$'))
  {
    report += '\nThe remote Debian system is :\n' + buf;
    debrel = chomp(buf);
    if (debrel == "testing/unstable") might_be_ubuntu = 1;

    buf = info_send_cmd(cmd:'COLUMNS=160 dpkg -l');

    if (buf)
    {
      if ( egrep(string:buf, pattern:"-[0-9]ubuntu[0-9]") ) might_be_ubuntu++;
      if ( might_be_ubuntu > 1 )
	 {
	  buf2 =  info_send_cmd(cmd: 'cat /etc/lsb-release');
        if ("DISTRIB_ID=Ubuntu" >< buf2)
        {
          set_kb_item(name: "Host/Ubuntu", value: TRUE);
          report += 'This is a Ubuntu system\n';
          debrel = NULL;
          x = egrep(string: buf2, pattern: "DISTRIB_RELEASE=");
          if (x) v = split(x, sep: '='); 
          if (x && max_index(v) > 0)
           set_kb_item(name: "Host/Ubuntu/release", value: v[1]);
         }
       }

      report += '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/Debian/dpkg-l", value:buf);
      set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
      security_note(port:port, data:report);
    }
    else
    {
      report += 
'For any reason, dpkg did not produce any result, therefore local security 
checks have been disabled';
    security_note(port:port, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'dpkg' did not return any result");
    }
    if (debrel)
     set_kb_item(name:"Host/Debian/release", value: debrel);
    exit(0);
  }

###################### Slackware ########################################

  buf = info_send_cmd(cmd: 'cat /etc/slackware-version');

  if ("Slackware" >< buf)
  {
    buf = ereg_replace(string: buf, pattern: "^Slackware +", replace: "");
    report += '\nThe remote Slackware system is :\n' + buf;
    if (buf !~ '^[0-9.]+[ \t\r\n]*$')
    {
      report += '\nThe Slackware version is unknown, therefore 
local security checks have been disabled\n';
      security_note(port:port, data:report);
      exit(0);
    }
    set_kb_item(name:"Host/Slackware/release", value: chomp(buf));

    buf = info_send_cmd(cmd: 'ls -1 /var/log/packages');

    if (buf)
    {
      report += '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/Slackware/packages", value:buf);
      set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
      security_note(port:port, data:report);
    }
    else
    {
      report += 
'For any reason, /var/log/packages/ could not be read, 
therefore local security checks have been disabled';
    set_kb_item(name:'HostLevelChecks/failure', value:"'/var/log/packages' could not be read");
    security_note(port:port, data:report);
    }
    exit(0);
  }

  report += 
'\nThe remote Linux distribution is not supported, therefore local security checks have not been enabled';
  security_note(port:port, data:report);
  set_kb_item(name:'HostLevelChecks/failure', value:"Unsupported Linux distribution");
  exit(0);
}
######################## MacOS X ###########################################
else if ("Darwin" >< buf )
 {
  operating_system = ereg_replace(pattern:"^.*Darwin Kernel Version ([0-9]+\.[0-9]+\.[0-9]+):.*$", string:buf, replace:"\1");

  num = split(operating_system, sep:".", keep:FALSE);
  version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + int(num[1]);


  buf = info_send_cmd(cmd: 'cat /private/etc/sysctl-macosxserver.conf');

  if ( "# /etc/sysctl-macosxserver.conf is reserved " >< buf  ) version = version + " Server";
  set_kb_item(name:"Host/MacOSX/Version", value:version);

  buf = info_send_cmd(cmd: 'ls /Library/Receipts');

  if ( ! buf )
  {
   report += 
'\nIt was not possible to get the list of installed package on the 
remote MacOS X system, therefore local security checks have
been disabled';
   security_note(port:port, data:report);
   set_kb_item(name:'HostLevelChecks/failure', value:"Could not obtain the list of installed packages");
   exit(0);
  }
  set_kb_item(name:"Host/MacOSX/packages", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  security_note(port:port, data:report);
 }
######################## Solaris ###########################################
else if ( egrep(pattern:"SunOS.*", string:buf) )
{
 buf = info_send_cmd(cmd: 'showrev -a');

 if ( ! buf )
 {
  report += 
'\nIt was not possible to gather the list of installed packages on the
remote Solaris system, therefore local security checks have been disabled.';
  security_note(port:port, data:report);
  set_kb_item(name:'HostLevelChecks/failure', value:"'showrev -a' failed");
  exit(0);
 }

 set_kb_item(name:"Host/Solaris/showrev", value:buf);

 buf = egrep(pattern:"^Release: ", string:buf);
 buf -= "Release: ";
 set_kb_item(name:"Host/Solaris/Version", value:buf);

 buf = info_send_cmd(cmd: "/usr/bin/pkginfo");

 if ( ! buf ) {
report = '\nIt was not possible to gather the list of installed packages on the
remote Solaris system, therefore local security checks have been disabled.';
  security_note(port:port, data:report);
  set_kb_item(name:'HostLevelChecks/failure', value:"'pkginfo' failed");
  exit(0);
 }

  set_kb_item(name:"Host/Solaris/pkginfo", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  security_note(port:port, data:report);
}
############################# AIX ##############################################
else if ( "AIX" >< buf )
{
  release = ereg_replace(pattern:".*AIX[ ]+.*[ ]+([0-9]+[ ]+[0-9]+)[ ]+.*", replace:"\1", string:buf);
  items = split(release, sep:" ", keep:0);
  release = "AIX-" + items[1] + "." + items[0];
  set_kb_item(name:"Host/AIX/version", value:release); 

  buf = info_send_cmd(cmd: "oslevel -r");

  if ( buf )  set_kb_item(name:"Host/AIX/oslevel", value:buf);

  buf = info_send_cmd(cmd: "lslpp -Lc");

  if ( ! buf ) {
    report += 
'\nThe command "lslpp -Lc" did not return any result, therefore
AIX local security checks have not been enabled for
this test';
    security_note(port:port, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'lslpp -Lc' failed");
    exit(0);
  }
  set_kb_item(name:"Host/AIX/lslpp", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  security_note(port:port, data:report);
  exit(0);
}
############################# HP-UX ##############################################
else if ( "HP-UX" >< buf )
{
  release = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.([0-9]+\.+[0-9]+)[ ]+.*", replace:"\1", string:buf);
  set_kb_item(name:"Host/HP-UX/version", value:release); 

  if ("ia64" >< buf)
    hardware = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.[0-9]+\.+[0-9]+[ ]+.[ ]+ia64.*", replace:"800", string:buf);
  else
    hardware = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.[0-9]+\.+[0-9]+[ ]+.[ ]+[0-9]+/(7|8)[0-9]+.*", replace:"\100", string:buf);
  set_kb_item(name:"Host/HP-UX/hardware", value:hardware); 
  buf = info_send_cmd(cmd:"/usr/sbin/swlist -l fileset -a revision");
  if ( !buf )  {
    report += 
'\nThe command "swlist -l fileset -a revision" did not return any result,
therefore HP-UX local security checks have not been enabled for
this test';
    security_note(port:port, data:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'swlist -l fileset -a revision' failed");
    exit(0);
  }

  set_kb_item(name:"Host/HP-UX/swlist", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  security_note(port:port, data:report);
  exit(0);
}


#------------------------------------------------------------------------#
# Misc calls (all Unixes)						 #
#------------------------------------------------------------------------#

# cfengine version 

ver = info_send_cmd(cmd:"/usr/sbin/cfservd --help | grep ^cfengine | cut -d '-' -f 2");
if ( ver )
 {
 ver = chomp(ver);
 set_kb_item(name:string("cfengine/version"), value:ver);
 }

buf = info_send_cmd(cmd: '/sbin/ifconfig -a');
if ( buf ) set_kb_item(name:"Host/ifconfig", value:buf);

if (info_t == INFO_SSH) ssh_close_connection();
else if (sock) close(sock);
