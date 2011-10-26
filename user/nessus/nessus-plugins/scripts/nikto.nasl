#TRUSTED 3c1a48ca36be1bc5b994ea62f4b669550b2fe5ca244b239bc4c903558f76c4c2af04fe900566b5bc37c0592178b004f39e971b972ca44a4e0ea7793a043742196103be6df8126e33c46779ee6389ff4eb2a4a532fcd7d439005f84989b415df978fbad243e3e5c6d96057c919283c23a967901203845ca14692c2799ca6e77f5b4b37862bd509d3ac6975c97f0a47f3f783aa649cb4e3f0fa5bd13a0b520a9c3d74792c86b3349cc05aacabcce71f1a1ad9f71f81aeaf54cc30bf9eed29068e51eb40fd3b5cbe26580f759c9d7a02890c06522c2a2b3d459ad116b95732ecf7ffc096bb076b3eac417c50ead321ae061b842d388509eda641bb74b4515ee4ceeef4f9fa262216ab7e9c61d2fabb9323635fa0ed3551e125baeedb83616064449080489fccf3a66c9b29e5b97c9f343d934868c41d6dd4548d847816d8f50085dd507adee70eb450ab686ce83bad92af36f5362aaf4719dbfb5fad6ba55b1a90e08de6e7266ceac64cdd0b56aaba1058bbad3bd5a942fea05f5ebf0927e2814a2b7a80bacd93922c2133ec17a400fdade0ef24c8ffea1f8a7b58e13699f3b9e0809510d054dafbec447217906d295e5769bd9b10ea57945f523947f255956e46865fb9591a65423eb1c1889112f36e9e06eb86787572a2f53971d897aabaa3f282959b9205376bd0ae999967c1407e1d440ef40011b1a3a0ace44e234619324bc
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if ( ! defined_func("pread")) exit(0);
if ( ! find_in_path("nikto.pl") ) exit(0);


if(description)
{
 script_id(14260);
 script_version ("1.5");
 name["english"] = "Nikto (NASL wrapper)";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs nikto(1) to find CGI.
See the section 'plugins options' to configure it

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Find CGI with Nikto";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencies("find_service.nes", "httpver.nasl", "logins.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

# script_add_preference(name:"Force scan all possible CGI directories",
#                       type:"checkbox", value:"no");
 script_add_preference(name:"Force full (generic) scan", 
                      type:"checkbox", value:"no");
 exit(0);
}

#

if (! defined_func("pread"))
{
  set_kb_item(name: "/tmp/UnableToRun/14254", value: TRUE);
  display("Script #14254 (nikto_wrapper) cannot run\n");
  exit(0);
}

user = get_kb_item("http/login");
pass = get_kb_item("http/login");
ids = get_kb_item("/Settings/Whisker/NIDS");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0);

# Nikto will generate many false positives if the web server is broken
no404 = get_kb_item("www/no404/" + port);
if ( no404 ) exit(0);

i = 0;
argv[i++] = "nikto.pl";

httpver = get_kb_item("http/"+port);
if (httpver == "11")
{
  argv[i++] = "-vhost";
  argv[i++] = get_host_name();
}

argv[i++] = "-h"; argv[i++] = get_host_ip();
argv[i++] = "-p"; argv[i++] = port;

encaps = get_port_transport(port);
if (encaps > 1) argv[i++] = "-ssl";

#p = script_get_preference("Force scan all possible CGI directories");
#if ("yes" >< p) argv[i++] = "-allcgi";
p = script_get_preference("Force full (generic) scan");
if ("yes" >< p) argv[i++] = "-gener";

if (idx && idx != "X")
{
  argv[i++] = "-evasion";
  argv[i++] = ids[0];
}

if (user)
{
  if (pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread(cmd: "nikto.pl", argv: argv, cd: 1);
if (! r) exit(0);	# error

report = 'Here is the Nikto report:\n';
foreach l (split(r))
{
  #display(j ++, "\n");
  l = ereg_replace(string: l, pattern: '^[ \t]+', replace: '');
  if (l[0] == '+' || l[0] == '-' || ! match(pattern: "ERROR*", string: l))
    report += l;
}

security_note(port: port, data: report);
