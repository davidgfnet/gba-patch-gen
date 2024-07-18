
Patching system internals
=========================

Patching needs usually involve:

 - Nullifying instructions (overwriting with nops)
 - Replacing some instructions or data
 - Adding some extra code either within or outside de ROM memory area

To these requirements we also add some of our own, such as requiring the patch
database to be easy to read and have a compact C representation.

Patching format
---------------

For each game entry, identified by game ID and version (5 bytes) information
about WAITCNT patches and backup storage patches is present.

Patches are a list of "instructions" that the patcher must execute in order to
patch the ROM before its execution. These instructions are encoded as a list
of 32 bit words in the following format:

  - 4 bits for an opcode
  - 3 bits for a numeric argument
  - 25 bits that encode the ROM offset

The following opcodes exist:

  - 0x0: Write buffer #N (0..7) to the specified address
  - 0x1: Overwrite N instructions at the specified address with a Thumb nop (0x46C0)
  - 0x2: Overwrite N instructions at the specified address with an ARM nop (0xE1A00000)
  - 0x3: Patch address with 1-8 bytes from the following word
  - 0x4: Patch address with the N (1..8) subsequent words.

Each patching database comes with a set of up to 8 buffers. These are sequences
of arbitrary bytes of arbitrary length up to 60 bytes. These are global for the
whole database (shared).


Save/Backup patches
===================

The save patcher tool is able to find patching locations for Flash and EEPROM
based storage, SRAM is assumed to be supported by all flash carts.

The patcher finds these locations and generates a list of addresses, so that
the cart patcher can overwrite them with proper replacements (usually an SRAM
based emulation).

It is possible to guess the save type used by an official game by looking for
certain magic strings that are embedded in the official SDK. These have
different variants depending on the version (SDK version most likely) but
also on the specific memory type (mostly Flash flavours).

Save patches use a couple of the previously mentioned opcodes and sub-opcodes
for each handler type:

  - 0x8: EEPROM handler addresses
     - 0x0: EEPROM read handler
     - 0x1: EEPROM write handler
  - 0x9: FLASH handler addresses
     - 0x0: Flash read handler
     - 0x1: Flash erase chip handler
     - 0x2: Flash erase sector handler
     - 0x3: Flash write sector handler
     - 0x4: Flash write byte handler

EEPROM
------

By far the easiest format after SRAM. There are usually two functions that
need patching: read and write handlers. They will usually take an address and
a buffer and will perform some read/write operation. These work on 8 byte
blocks, expanded into bit buffers (so 64 byte buffers containing 64 bits).

There are a bunch of versions and revisions of these functions, but the
interface remains unchanged. The read/write addresses are stored in the
patch database, but the actual replacement depends on the patcher.

FLASH
-----

There's a bunch of devices and manufacturers, each with their own quirks.
In general flash is 64KB, however certain Pokemon games ship 128KB. Since
it is not possible to map more than 64KB at a time (this seems to be a GBA
limitation on the address space mapping) they use a bank-switch command to
access the high/low parts of the device.

Most devices user 4KiB blocks that need to be erased before any write
can happen. There's also a full-device clear command. Atmel devices are weird
and tricky since they use a 128byte block size, and a single erase-and-write
command.

The SDK has a bunch of functions to interface flash devices: flash identify,
data read, write sector, full chip erase and sector erase. Some newer SDKs
do expose a byte-level write function, but it seems widely unused. 
The identify and read functions are common to all device types, however the
rest can have device-specific functions (depending on the quirks of each
individual devices).

The patcher will usually patch the identify function to return a hardcoded
device ID (since it is necessary to perform any operation) and let the firmware
patch the read/write/erase functions with the relevant handlers.


