# bakassabl
A (very) cheap Linux sandboxer based on seccomp


## Compilation
```bash
 $ make
or manually
 $ ./gen_bakassabl.h.sh > bakassabl.h
 $ cc -o bakassabl -Werror -O3 -fPIE -fPIC -fstack-protector-all -Wl,-z,relro bakassabl.c -lseccomp -pie
```

## Installation

```bash
$ sudo make install
```

`bakassabl` will be installed in `/usr/local/bin`.

##  Examples

Given commands are equivalent.

### No more privilege
```bash
 $ bakassabl --verbose --paranoid  -- /bin/ping -c 10 localhost
or
 $ bakassabl -v -P -- /bin/ping -c 10 localhost
```

### Black-listing syscalls
Pour interdire `ncat` d'utiliser le syscall `connect`:
```bash
 $ bakassabl --verbose --allow-all --deny connect -- /usr/bin/ncat -v4 localhost 22
or
 $ bakassabl -v -A -d connect -- /usr/bin/ncat -v4 localhost 22
```

Pour interdire `firefox` d'ouvrir une socket de type AF_INET:
```bash
$ bakassabl --allow-all --no-internet -- /opt/firefox/firefox-bin
```

### White-listing syscalls
```bash
 $ bakassabl --verbose --deny-all  --allow exit -- ./myexit
or
 $ bakassabl -v -D -a exit -- ./myexit
```



## Author
* @_hugsy_
