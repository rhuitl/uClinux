/^(\/\/)?#define TLG_/ && ! /^(\/\/)?#define TLG_FEATURE/  {
	envname = "CONFIG_USER_TINYLOGIN_" substr($2, 5)
	envval = ENVIRON[envname]
	$1 = (envval == "y") ? "#define" : "//#define"
	print $0
}
/^(\/\/)?#define TLG_FEATURE/ {
	envname = "CONFIG_USER_TINYLOGIN_" substr($2, 13)
	envval = ENVIRON[envname]
	$1 = (envval == "y") ? "#define" : "//#define"
	print $0
}
! /^(\/\/)?#define TLG_/ {
	print
}
