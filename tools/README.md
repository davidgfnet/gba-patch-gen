
Patching tools
==============

Here there's a collection of tools for patch generation.

 * waitcnt\_finder.py: Processes ROMs to find WAITCNT patching sites. The output
   contains a set of instructions to nullify (usually store instructions) and
   data sites to override (usually to patch an address). It uses a mixture of
   constant search and symbolic emulation to determine relevant patching sites.

 * swi1\_finder.py: Similar to waitcnt\_finder, finds SWI 0x1 calls (to the GBA
   BIOS) that result in WAITCNT zeroing. Its purpose is to patch the ROM to
   maintain the original WAITCNT value. This is optional in the sense that it
   is not strictly required but helps game performance (ie. by preserving the
   gamepak bus prefetch bit).

 * irq\_finder.py: Finds instructions and/or literal values where a game updates
   its IRQ handler function address. This address is placed at 0x03007FFC (or
   some mirror) and is used by the BIOS to pass interrupts to a user-defined
   routine. The output produced is a mixture of literal values but also str
   instructions that update said address. The patcher can decide to either
   patch the pool address or the store instruction. It is also capable of
   detecting certain memset code that results in 0x03007FF4 being cleared.
   This address is used as a shadow IRQ handler address and must be preserved.

 * save\_finder.py: Since FLASH and EEPROM are unavailable as storage mediums
   this script finds the relevant storage routines and produces patch
   information for them. A list of routine addresses is produced.

 * rtc\_finder.py: Finds RTC routines by looking for certain function prologues
   and produces a list of function addresses so that they can be hooked.

 * layout\_finder.py: Produces some free-space / hole / header information for
   ROMs. The purpose is to enable certain patching methods to succeed. In
   particular to inject code at certain distances or for big ROMs (like 32MB).
   Some thumb instructions have a limited branch range, so they might need
   some free ROM space to properly patch certain functionality.

Some tools are provided to manage patch information:

 * patch\_merge.py: Merges a set of patches (of different types) and produces a
   single file with all the patch information. This script indexes patches on
   game code and version, trying to reconcile any "duplicated" ROMs (like
   variants or patched versions / minor revisions) as well as compatible
   patches. The merge might fail if contradictory information exists in some
   cases.

The actual patch generation is provided by patch\_gen.py. Given a single full
patch (produced by the merge tool) generates the actual patching data, making
some decisions on how each relevant patch sites are handled. Roughly:

 - Patching WAITCNT updates with NOP instructions.
 - Patching SWI 0x1 with branches to an emulation routine.
 - Adding some extra code to handle the above mentioned SWI.
 - Patching IRQ handlers sites to point to 0x03007FF4.
 - Patching some FLASH routines.
 - Encoding some FLASH/EEPROM routines (for the firmware to patch).
 - Encoding RTC routines.


