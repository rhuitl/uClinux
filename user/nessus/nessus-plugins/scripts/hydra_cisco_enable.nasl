#TRUSTED 2874ab8fd7e6e352fe8f743223e03e70d57f5459dda934cf1090e279fcc709aaa02ee35e3ffdbbba2e8ae8f6e055adaa3005ba6b62ea9345af3a9631ca42d5204e5a7883ade42b7988d19576a5728d0eba0b5a417d958bd32fd56c082b52eb13ecc3d030a6e09a5354d9c98afc4b81f23cfc5e6d8e346b71ac98c886da092b483b1b159afe540b026e94060cb9a7159c68f41fe586c6a12340f2b63626d306f2e8ee5bb49910d9cafcb62939b5182babd832a349bdde831724b195af478183ddfc77c259aab4abe489eddb18af9a4e39d2ad70ef5ebaa478528bfac4dec450b03c823f3e5371140f5f2084e288b074935d2f7f52d1a51b3d7fddaaf83e43b04cd3fdb6dff262c3b2795f0582e9cfd7d2af78cd28c4307c68473f377362004a4c09e0f14b02d98c294b819fd78ad9666830a1ca49ed48ebd60aac20244680802766ae67c7d7c038e0783e74fbf8eddf13d700927376471dfeb66b21c837737851c20aef372ded999b3ece7d18ac2bcaf73a23156eedcfe183d1d28c734b86e3924b8da06e99ff7ea0d91c305f301647df1dde01d4551e414c6698bb7a39bd8c0d918ed44b950e565e99e18e92d8453c3ebd578374e72e5aa2c5c31c2f8e10b77f3ded7e0ce189609d1a87d9999ce816a141d8b950ad94d097b2162f6d95d4347920f4c3a3dc5a91d0d9541442193a470a4d4a5a34609575e261201101a96b412d
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);


if(description)
{
 script_id(15870);
 script_version ("1.2");
 name["english"] = "Hydra: Cisco enable";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find Cisco 'enable' passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force 'Cisco enable' authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_add_preference(name: "Logon password : ", type: "entry", value: "");

 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_timeout(0);
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/passwords_file");
 script_require_ports("Services/telnet", 23);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl", "hydra_cisco.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd == NULL) exit(0);

port = get_kb_item("Services/telnet");
if (! port) port = 23;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);
r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >!< r) exit(0);

# Logon password is required
pass = script_get_preference("Logon password : ");
if (! pass)
{
 l = get_kb_list("Hydra/cisco/"+port);
 if (isnull(l)) exit(0);
 foreach pass (l)
   if (! pass)
    break;
 if (! pass) exit(0);
}

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-P"; argv[i++] = passwd;
if (empty)
{
  argv[i++] = "-e"; argv[i++] = "n";
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "cisco-enable";
argv[i++] = pass;

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    # l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: "Hydra/cisco-enable/"+port, value: p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to find the following Cisco enable passwords:\n' + report);
