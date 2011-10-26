#! /bin/sh

# If it doesn't exist, kill it.
[ "`insmod nonexistent-file 2>&1`" = "insmod: can't read 'nonexistent-file': No such file or directory" ]

# Make sure it passes module correctly.
SIZE=$(echo `wc -c < tests/test-insmod/02simple.sh`)
[ "`insmod tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]

# Check options passed intact.
[ "`insmod tests/test-insmod/02simple.sh a`" = "INIT_MODULE: $SIZE a " ]
[ "`insmod tests/test-insmod/02simple.sh a b`" = "INIT_MODULE: $SIZE a b " ]
