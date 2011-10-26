#! /bin/sh
# Test for spaces in configuration files: based on 04config.sh

for BITNESS in 32 64; do

# Simple dump out test.
[ "`modprobe -C /dev/null -c 2>&1`" = "" ]
[ "`modprobe --config /dev/null --showconfig 2>&1`" = "" ]

# Explicitly mentioned config files must exist.
[ "`modprobe -C FILE-WHICH-DOESNT-EXIST foo 2>&1`" = "FATAL: Failed to open config file FILE-WHICH-DOESNT-EXIST: No such file or directory" ]

# Default one doesn't have to.
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH1=/dev/null
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH2=FILE-WHICH-DOESNT-EXIST:
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2
[ "`modprobe foo 2>&1`" = "FATAL: Module foo not found." ]

# Create a simple config file.
cat > tests/tmp/modprobe.conf <<EOF
# Various aliases
alias   alias_to_foo   foo
alias   alias_to_bar   bar
alias   alias_to_export_dep-$BITNESS   export_dep-$BITNESS
alias   alias_to_noexport_dep-$BITNESS   noexport_dep-$BITNESS
alias   alias_to_noexport_nodep-$BITNESS   noexport_nodep-$BITNESS
alias   alias_to_noexport_doubledep-$BITNESS   noexport_doubledep-$BITNESS

# Various options, including options to aliases.
options   alias_to_export_dep-$BITNESS   I am alias to export_dep
options   export_dep-$BITNESS   I am export_dep
options   alias_to_noexport_dep-$BITNESS   I am alias to noexport_dep
options   noexport_dep-$BITNESS   I am noexport_dep
options   alias_to_noexport_nodep-$BITNESS   I am alias to noexport_nodep
options   noexport_nodep-$BITNESS   I am noexport_nodep
options   alias_to_noexport_doubledep-$BITNESS   I am alias to noexport_doubledep
options   noexport_doubledep-$BITNESS   I am noexport_doubledep

# Install commands
install   bar   echo Installing   bar
install   foo   echo Installing   foo
install   export_nodep-$BITNESS   echo Installing   export_nodep

# Remove commands
remove   bar   echo Removing   bar
remove   foo   echo Removing   foo
remove   export_nodep-$BITNESS   echo Removing   export_nodep

# Finally, an include
include   tests/tmp/modprobe.conf.included
EOF

# Now create this included file
cat > tests/tmp/modprobe.conf.included <<EOF
install   baz   echo Installing   baz
remove   baz   echo Removing   baz

alias   alias_to_baz   baz
EOF

# Inputs
MODTEST_OVERRIDE1=/lib/modules/$MODTEST_UNAME
MODTEST_OVERRIDE_WITH1=tests/data/$BITNESS/normal
export MODTEST_OVERRIDE1 MODTEST_OVERRIDE_WITH1

MODTEST_OVERRIDE2=/lib/modules/$MODTEST_UNAME/export_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH2=tests/data/$BITNESS/normal/export_dep-$BITNESS.ko
export MODTEST_OVERRIDE2 MODTEST_OVERRIDE_WITH2

MODTEST_OVERRIDE3=/lib/modules/$MODTEST_UNAME/noexport_dep-$BITNESS.ko
MODTEST_OVERRIDE_WITH3=tests/data/$BITNESS/normal/noexport_dep-$BITNESS.ko
export MODTEST_OVERRIDE3 MODTEST_OVERRIDE_WITH3

MODTEST_OVERRIDE4=/lib/modules/$MODTEST_UNAME/noexport_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH4=tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko
export MODTEST_OVERRIDE4 MODTEST_OVERRIDE_WITH4

MODTEST_OVERRIDE5=/lib/modules/$MODTEST_UNAME/export_nodep-$BITNESS.ko
MODTEST_OVERRIDE_WITH5=tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko
export MODTEST_OVERRIDE5 MODTEST_OVERRIDE_WITH5

MODTEST_OVERRIDE6=/lib/modules/$MODTEST_UNAME/noexport_doubledep-$BITNESS.ko
MODTEST_OVERRIDE_WITH6=tests/data/$BITNESS/normal/noexport_doubledep-$BITNESS.ko
export MODTEST_OVERRIDE6 MODTEST_OVERRIDE_WITH6

MODTEST_OVERRIDE7=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH7=tests/tmp/modules.dep
export MODTEST_OVERRIDE7 MODTEST_OVERRIDE_WITH7

MODTEST_OVERRIDE8=/etc/modprobe.conf
MODTEST_OVERRIDE_WITH8=tests/tmp/modprobe.conf
export MODTEST_OVERRIDE8 MODTEST_OVERRIDE_WITH8

MODTEST_OVERRIDE9=/etc/modprobe.conf.included
MODTEST_OVERRIDE_WITH9=tests/tmp/modprobe.conf.included
export MODTEST_OVERRIDE9 MODTEST_OVERRIDE_WITH9

MODTEST_OVERRIDE10=/lib/modules/$MODTEST_UNAME/modules.dep
MODTEST_OVERRIDE_WITH10=tests/tmp/modules.dep
export MODTEST_OVERRIDE10 MODTEST_OVERRIDE_WITH10

MODTEST_OVERRIDE11=/proc/modules
MODTEST_OVERRIDE_WITH11=FILE-WHICH-DOESNT-EXIST
export MODTEST_OVERRIDE11 MODTEST_OVERRIDE_WITH11

# Now create modules.dep
cat > tests/tmp/modules.dep <<EOF
/lib/modules/2.5.52/noexport_nodep-$BITNESS.ko:
/lib/modules/2.5.52/noexport_doubledep-$BITNESS.ko: /lib/modules/2.5.52/export_dep-$BITNESS.ko /lib/modules/2.5.52/export_nodep-$BITNESS.ko
/lib/modules/2.5.52/noexport_dep-$BITNESS.ko: /lib/modules/2.5.52/export_nodep-$BITNESS.ko
/lib/modules/2.5.52/export_nodep-$BITNESS.ko:
/lib/modules/2.5.52/export_dep-$BITNESS.ko: /lib/modules/2.5.52/export_nodep-$BITNESS.ko
EOF

SIZE_NOEXPORT_NODEP=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_nodep-$BITNESS.ko`)
SIZE_EXPORT_NODEP=$(echo `wc -c < tests/data/$BITNESS/normal/export_nodep-$BITNESS.ko`)
SIZE_NOEXPORT_DEP=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_dep-$BITNESS.ko`)
SIZE_EXPORT_DEP=$(echo `wc -c < tests/data/$BITNESS/normal/export_dep-$BITNESS.ko`)
SIZE_NOEXPORT_DOUBLEDEP=$(echo `wc -c < tests/data/$BITNESS/normal/noexport_doubledep-$BITNESS.ko`)

# Test ignoring install & remove.

[ "`modprobe --ignore-install export_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_EXPORT_NODEP " ]
[ "`modprobe -i export_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_EXPORT_NODEP " ]
[ "`modprobe -i foo 2>&1`" = "FATAL: Module foo not found." ]
[ "`modprobe -r --ignore-remove export_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: export_nodep_$BITNESS EXCL " ]
[ "`modprobe -r -i export_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: export_nodep_$BITNESS EXCL " ]
[ "`modprobe -i -r foo 2>&1`" = "FATAL: Module foo not found." ]

# Test install & remove (fake modules)
[ "`modprobe foo 2>&1`" = "SYSTEM: echo Installing   foo" ]
[ "`modprobe bar 2>&1`" = "SYSTEM: echo Installing   bar" ]
[ "`modprobe baz 2>&1`" = "SYSTEM: echo Installing   baz" ]
[ "`modprobe -r foo 2>&1`" = "SYSTEM: echo Removing   foo" ]
[ "`modprobe -r bar 2>&1`" = "SYSTEM: echo Removing   bar" ]
[ "`modprobe -r baz 2>&1`" = "SYSTEM: echo Removing   baz" ]

# Test install & remove of a what is also a real module.
[ "`modprobe export_nodep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep" ]
[ "`modprobe -r export_nodep-$BITNESS 2>&1`" = "SYSTEM: echo Removing   export_nodep" ]

# Test install & remove of what is also a real module via dependency.
[ "`modprobe noexport_dep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_NOEXPORT_DEP I am noexport_dep" ]
[ "`modprobe -r noexport_dep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_dep_$BITNESS EXCL 
SYSTEM: echo Removing   export_nodep" ]

# Test ignoring install & remove: only effects commandline.
[ "`modprobe -i noexport_dep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_NOEXPORT_DEP I am noexport_dep" ]
[ "`modprobe -r -i noexport_dep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_dep_$BITNESS EXCL 
SYSTEM: echo Removing   export_nodep" ]

# Test options
[ "`modprobe noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP I am noexport_nodep" ]
[ "`modprobe noexport_nodep-$BITNESS OPTIONS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP OPTIONS I am noexport_nodep" ]

[ "`modprobe noexport_dep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_NOEXPORT_DEP I am noexport_dep" ]
[ "`modprobe noexport_dep-$BITNESS OPTIONS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_NOEXPORT_DEP OPTIONS I am noexport_dep" ]

[ "`modprobe export_dep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP I am export_dep" ]
[ "`modprobe export_dep-$BITNESS OPTIONS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP OPTIONS I am export_dep" ]

[ "`modprobe noexport_doubledep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP I am export_dep
INIT_MODULE: $SIZE_NOEXPORT_DOUBLEDEP I am noexport_doubledep" ]
[ "`modprobe noexport_doubledep-$BITNESS OPTIONS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP I am export_dep
INIT_MODULE: $SIZE_NOEXPORT_DOUBLEDEP OPTIONS I am noexport_doubledep" ]

# Test aliases doing insertion.
[ "`modprobe alias_to_noexport_nodep-$BITNESS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP I am alias to noexport_nodep I am noexport_nodep" ]
[ "`modprobe alias_to_noexport_nodep-$BITNESS OPTIONS 2>&1`" = "INIT_MODULE: $SIZE_NOEXPORT_NODEP OPTIONS I am alias to noexport_nodep I am noexport_nodep" ]

[ "`modprobe alias_to_noexport_dep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_NOEXPORT_DEP I am alias to noexport_dep I am noexport_dep" ]
[ "`modprobe alias_to_noexport_dep-$BITNESS OPTIONS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_NOEXPORT_DEP OPTIONS I am alias to noexport_dep I am noexport_dep" ]

[ "`modprobe alias_to_export_dep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP I am alias to export_dep I am export_dep" ]
[ "`modprobe alias_to_export_dep-$BITNESS OPTIONS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP OPTIONS I am alias to export_dep I am export_dep" ]

[ "`modprobe alias_to_noexport_doubledep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP I am export_dep
INIT_MODULE: $SIZE_NOEXPORT_DOUBLEDEP I am alias to noexport_doubledep I am noexport_doubledep" ]
[ "`modprobe alias_to_noexport_doubledep-$BITNESS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP I am export_dep
INIT_MODULE: $SIZE_NOEXPORT_DOUBLEDEP I am alias to noexport_doubledep I am noexport_doubledep" ]
[ "`modprobe alias_to_noexport_doubledep-$BITNESS OPTIONS 2>&1`" = "SYSTEM: echo Installing   export_nodep
INIT_MODULE: $SIZE_EXPORT_DEP I am export_dep
INIT_MODULE: $SIZE_NOEXPORT_DOUBLEDEP OPTIONS I am alias to noexport_doubledep I am noexport_doubledep" ]

[ "`modprobe alias_to_foo 2>&1`" = "SYSTEM: echo Installing   foo" ]
[ "`modprobe alias_to_bar 2>&1`" = "SYSTEM: echo Installing   bar" ]
[ "`modprobe alias_to_baz 2>&1`" = "SYSTEM: echo Installing   baz" ]

# Test aliases doing removal.
[ "`modprobe -r alias_to_noexport_nodep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_nodep_$BITNESS EXCL " ]
[ "`modprobe -r alias_to_noexport_dep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_dep_$BITNESS EXCL 
SYSTEM: echo Removing   export_nodep" ]
[ "`modprobe -r alias_to_export_dep-$BITNESS 2>&1`" = "DELETE_MODULE: export_dep_$BITNESS EXCL 
SYSTEM: echo Removing   export_nodep" ]
[ "`modprobe -r alias_to_noexport_doubledep-$BITNESS 2>&1`" = "DELETE_MODULE: noexport_doubledep_$BITNESS EXCL 
DELETE_MODULE: export_dep_$BITNESS EXCL 
SYSTEM: echo Removing   export_nodep" ]

[ "`modprobe -r alias_to_foo 2>&1`" = "SYSTEM: echo Removing   foo" ]
[ "`modprobe -r alias_to_bar 2>&1`" = "SYSTEM: echo Removing   bar" ]
[ "`modprobe -r alias_to_baz 2>&1`" = "SYSTEM: echo Removing   baz" ]

done
