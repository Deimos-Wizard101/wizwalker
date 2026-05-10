"""
Diagnostic tool for SpellListControl memory layout.

Probes the SpellList vector metadata, tests stride candidates, dumps
raw hex, and scans field offsets to help identify the correct stride
and field layout when spells are being read incorrectly.

Prerequisites:
  - Wizard101 must be running
  - Spellbook must be open on the Deck page (SpellList visible)

Usage:
  py debug_spell_list.py
"""

import asyncio
import struct

from wizwalker import ClientHandler
from wizwalker.constants import Primitive
from wizwalker.extensions.scripting.utils import _maybe_get_named_window
from wizwalker.memory.memory_object import DynamicMemoryObject
from wizwalker.memory.memory_objects.spell import DynamicGraphicalSpell
from wizwalker.memory.memory_objects.window import DynamicSpellListControl

STRIDE_CANDIDATES = [
    0x08, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28,
    0x30, 0x38, 0x40, 0x48, 0x50, 0x60, 0x70, 0x78,
    0x80, 0x90, 0xA0, 0xA8, 0xB0, 0xC0, 0xD0, 0xE0,
    0xF0, 0x100, 0x120, 0x150, 0x180, 0x200,
]


async def try_read_name(hook_handler, gfx_ptr: int) -> str | None:
    try:
        gfx = DynamicGraphicalSpell(hook_handler, gfx_ptr)
        template = await gfx.spell_template()
        if not template:
            return None
        name = await template.name()
        return name if name else None
    except Exception:
        return None


async def probe_entry(hook_handler, addr: int) -> tuple[int, str | None]:
    """Read graphical_spell pointer at offset 0 and try to get a name."""
    try:
        obj = DynamicMemoryObject(hook_handler, addr)
        gfx_ptr = await obj.read_value_from_offset(0x0, Primitive.uint64)
        if gfx_ptr == 0:
            return 0, None
        name = await try_read_name(hook_handler, gfx_ptr)
        return gfx_ptr, name
    except Exception:
        return 0, None


async def section_vector_metadata(ctrl: DynamicSpellListControl):
    print("=" * 60)
    print("SECTION 1: Vector metadata at offset 0x280")
    print("=" * 60)

    start_ptr = await ctrl.read_value_from_offset(0x280, Primitive.uint64)
    end_ptr_8  = await ctrl.read_value_from_offset(0x288, Primitive.uint64)
    end_ptr_16 = await ctrl.read_value_from_offset(0x290, Primitive.uint64)

    print(f"  start_ptr   (0x280) = 0x{start_ptr:016X}")
    print(f"  end_ptr@+8  (0x288) = 0x{end_ptr_8:016X}  "
          f"  range = {end_ptr_8 - start_ptr} bytes")
    print(f"  end_ptr@+16 (0x290) = 0x{end_ptr_16:016X}  "
          f"  range = {end_ptr_16 - start_ptr} bytes")
    print()
    print("  read_inlined_vector uses offset+16 (capacity?), "
          "read_shared_vector uses offset+8 (end).")
    print(f"  With stride 0xA8: offset+8  → {(end_ptr_8 - start_ptr) // 0xA8} entries")
    print(f"  With stride 0xA8: offset+16 → {(end_ptr_16 - start_ptr) // 0xA8} entries")
    print()

    return start_ptr, end_ptr_8, end_ptr_16


async def section_stride_probe(hook_handler, start_ptr: int, end_ptr: int):
    print("=" * 60)
    print("SECTION 2: Stride probe (using end_ptr@+8)")
    print("=" * 60)
    print(f"  {'stride':>8}  {'total':>6}  {'valid':>6}  {'named':>6}  names")
    print(f"  {'-'*8}  {'-'*6}  {'-'*6}  {'-'*6}  -----")

    best_stride = 0xA8
    best_named = 0
    results = []

    for stride in STRIDE_CANDIDATES:
        total = (end_ptr - start_ptr) // stride
        if total == 0 or total > 200:
            continue

        valid_count = 0
        named_count = 0
        sample_names = []

        for i in range(total):
            addr = start_ptr + i * stride
            gfx_ptr, name = await probe_entry(hook_handler, addr)
            if gfx_ptr != 0:
                valid_count += 1
            if name:
                named_count += 1
                if len(sample_names) < 3:
                    sample_names.append(name)

        names_str = ", ".join(f'"{n}"' for n in sample_names) if sample_names else "-"
        marker = " <--" if named_count > best_named else ""
        print(f"  0x{stride:06X}  {total:>6}  {valid_count:>6}  {named_count:>6}  "
              f"{names_str}{marker}")

        results.append((stride, total, valid_count, named_count, sample_names))
        if named_count > best_named:
            best_named = named_count
            best_stride = stride

    print()
    return best_stride, results


async def section_entry_dump(hook_handler, start_ptr: int, end_ptr: int, stride: int):
    print("=" * 60)
    print(f"SECTION 3: Per-entry dump  (stride=0x{stride:X})")
    print("=" * 60)

    total = (end_ptr - start_ptr) // stride
    for i in range(total):
        addr = start_ptr + i * stride
        try:
            obj = DynamicMemoryObject(hook_handler, addr)
            gfx_ptr  = await obj.read_value_from_offset(0x00, Primitive.uint64)
            max_cop  = await obj.read_value_from_offset(0x10, Primitive.uint32)
            cur_cop  = await obj.read_value_from_offset(0x14, Primitive.uint32)
            name = None
            if gfx_ptr != 0:
                name = await try_read_name(hook_handler, gfx_ptr)
            name_str = f'"{name}"' if name else ("(null ptr)" if gfx_ptr == 0 else "(unreadable)")
            print(f"  [{i:>3}] addr=0x{addr:X}  gfx=0x{gfx_ptr:016X}  "
                  f"max={max_cop}  cur={cur_cop}  name={name_str}")
        except Exception as e:
            print(f"  [{i:>3}] addr=0x{addr:X}  ERROR: {e}")

    print()


async def section_hex_dump(hook_handler, start_ptr: int, stride: int, n_entries: int = 3):
    print("=" * 60)
    print(f"SECTION 4: Raw hex dump  (first {n_entries} entries, stride=0x{stride:X})")
    print("=" * 60)

    size = stride * n_entries
    try:
        raw = await DynamicMemoryObject(hook_handler, start_ptr).read_bytes(start_ptr, size)
    except Exception as e:
        print(f"  ERROR reading bytes: {e}")
        print()
        return

    bytes_per_row = 16
    for row_start in range(0, len(raw), bytes_per_row):
        chunk = raw[row_start:row_start + bytes_per_row]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        entry_marker = ""
        if row_start % stride == 0:
            entry_marker = f"  ← entry {row_start // stride}"
        print(f"  +{row_start:04X}  {hex_part:<47}  {asc_part}{entry_marker}")

    print()


async def section_field_probe(hook_handler, start_ptr: int, stride: int):
    print("=" * 60)
    print(f"SECTION 5: Field offset probe on entry 0  (stride=0x{stride:X})")
    print("=" * 60)
    print("  Reading every 4-byte-aligned uint32 and uint64 up to min(stride, 0x100)")
    print()

    limit = min(stride, 0x100)
    obj = DynamicMemoryObject(hook_handler, start_ptr)

    print(f"  {'offset':>8}   {'uint32':>12}   {'uint64':>20}")
    print(f"  {'-'*8}   {'-'*12}   {'-'*20}")

    offset = 0
    while offset + 4 <= limit:
        try:
            v32 = await obj.read_value_from_offset(offset, Primitive.uint32)
        except Exception:
            v32 = None

        v64_str = ""
        if offset + 8 <= limit:
            try:
                v64 = await obj.read_value_from_offset(offset, Primitive.uint64)
                v64_str = f"0x{v64:016X}"
            except Exception:
                v64_str = "error"

        v32_str = f"{v32}" if v32 is not None else "error"
        print(f"  0x{offset:06X}   {v32_str:>12}   {v64_str}")
        offset += 4

    print()


async def main():
    handler = ClientHandler()
    clients = handler.get_new_clients()
    if not clients:
        print("No Wizard101 client found. Start the game first.")
        return

    client = clients[0]

    try:
        print("Activating root window hook...")
        await client.hook_handler.activate_root_window_hook()
        print("Ready.\n")

        try:
            deck_config = await _maybe_get_named_window(client.root_window, "DeckConfiguration")
        except ValueError:
            print("ERROR: DeckConfiguration window not found.")
            print("Open the spellbook and navigate to the Deck page first.")
            return

        try:
            spell_list_win = await _maybe_get_named_window(deck_config, "SpellList")
        except ValueError:
            print("ERROR: SpellList window not found inside DeckConfiguration.")
            return

        base_addr = await spell_list_win.read_base_address()
        print(f"SpellListControl base address: 0x{base_addr:X}\n")

        ctrl = DynamicSpellListControl(client.hook_handler, base_addr)

        start_ptr, end_ptr_8, end_ptr_16 = await section_vector_metadata(ctrl)

        if start_ptr == 0 or end_ptr_8 <= start_ptr:
            print("ERROR: Invalid vector pointers — is the SpellList window visible and populated?")
            return

        best_stride, _ = await section_stride_probe(client.hook_handler, start_ptr, end_ptr_8)

        print(f"Best stride determined: 0x{best_stride:X}\n")

        await section_entry_dump(client.hook_handler, start_ptr, end_ptr_8, best_stride)
        await section_hex_dump(client.hook_handler, start_ptr, best_stride)
        await section_field_probe(client.hook_handler, start_ptr, best_stride)

    finally:
        print("Closing...")
        await handler.close()
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
