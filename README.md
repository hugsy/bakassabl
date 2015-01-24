# bakassabl
A (very) cheap Linux sandboxer based on seccomp


## Compile
```
 $ make
or manually
 $ ./gen_bakassabl.h.sh > bakassabl.h
 $ cc -o bakassabl -Werror -O3 -fPIE -fPIC -fstack-protector-all -Wl,-z,relro bakassabl.c -lseccomp -pie
```


##  Examples

Given commands are equivalent.

### No more privilege
```
 $ ./bakassabl --verbose --paranoid  -- /bin/ping -c 10 localhost
or
 $ ./bakassabl -v -P -- /bin/ping -c 10 localhost
```

### Black-listing syscalls
```
 $ ./bakassabl --verbose --allow-all --deny connect -- /usr/bin/ncat -v4 localhost 22
or
 $ ./bakassabl -v -A -d connect -- /usr/bin/ncat -v4 localhost 22
```

### White-listing syscalls
```
 $ ./bakassabl --verbose --deny-all  --allow exit -- ./myexit
or
 $ ./bakassabl -v -D -a exit -- ./myexit
```

## ToDo
* deny-all mode is not fully operational


## Author
* @_hugsy_