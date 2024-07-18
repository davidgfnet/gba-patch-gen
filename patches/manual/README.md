
Here are some patches that were manually generated. The main reason is that it
is too complicated to automatically capture them and/or patch them correctly.

Currently NES emulated games have no patches at all and are not supported.

240002024 patches
-----------------

Some games have a weird routine to write certain data to memory (not only I/O
regs). They can be found using:

```
LANG=C grep --only-matching --byte-offset --binary --text --perl-regexp "\x04\x02\x00\x24\x14\x40" *.gba
```

These games have a routine that receives a constant byte stream and perform
certain memory writes based on their contents. The table has a format such as:

4 address/header bytes + 1/2/4 bytes payload

The header contains an address, with its 4 MSB having a number being 1, 2 or 4.
Once it reads the address (all accesses are performed at a byte level to
prevent alignment issues) it checks the MSB nibble to learn whether it's a
byte, half-word or word access, and will proceed to read the payload data
as well as writing it into the specified address.

The table typically contains several entries and ends with two zero words. In
the case of WAITCNT the table contains the entry 24000204 + 2 bytes. We simply
patch them to write to the address 04000206 instead (unused I/O reg). Clearing
the entry would result in the function interpreting it as a stop signal, which
is undesirable (won't write any other registers).

writehandler patches
--------------------

Some games use some function to write to I/O registers (or in general to write
to a 16 bit location in memory). Don't ask me why :)

We simply cannot patch the function/access and therefore we patch the function
call (the handler is used for other I/O regs we do not want to disrupt).

