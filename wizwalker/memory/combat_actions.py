"""Direct combat action injection via game messages.

Sends combat actions directly through the game's message system without any
UI interaction. Uses the proven CreateRemoteThread shellcode pattern.

Binary RE source: FUN_140d9cda0 (flee function — sends MSG_COMBATMOVE)

Supported messages:

    MSG_COMBATMOVE — standard combat actions (pass, cast, enchant, fusion, etc.)
        1. GameMessage::Create(buf, 0x10)
        2. GameMessage::SetType(game_client, buf, &"MSG_COMBATMOVE")
        3. GameMessage::GetField(buf, "MoveType")       -> SetInt32(field, value)
        4. GameMessage::GetField(buf, "SpellSelection")  -> SetInt32(field, value)
        5. GameMessage::GetField(buf, "SpellTarget")     -> SetInt32(field, value)
        6. GameMessage::GetField(buf, "EnchantmentID")   -> SetInt32(field, value)
        7. GameClientModules::Send(game_modules, buf, 0)
        8. GameMessage::Free(buf)

    MSG_COMBATDRAW — draw a treasure card from the TC deck
        1. GameMessage::Create(buf, 0x10)
        2. GameMessage::SetType(game_client, buf, &"MSG_COMBATDRAW")
        3. GameClientModules::Send(game_modules, buf, 0)
        4. GameMessage::Free(buf)
        (No fields — the message type alone triggers the draw.)

    MSG_PETWILLCAST — trigger a pet may-cast spell
        1. GameMessage::Create(buf, 0x10)
        2. GameMessage::SetType(game_client, buf, &"MSG_PETWILLCAST")
        3. GameMessage::GetField(buf, "PetCastingSpell") -> SetString(field, name, 0)
        4. GameMessage::GetField(buf, "Target")          -> SetInt32(field, value)
        5. GameClientModules::Send(game_modules, buf, 0)
        6. GameMessage::Free(buf)

MoveType enum (from FUN_142004af0):
    0  = Cast Spell
    1  = Flee
    2  = Discard
    3  = Pass
    4  = Unready
    5  = Cast Specific Spell
    6  = Cast Specific Spell With Pips
    7  = Planning Time Expired
    8  = Player Duel Time Expired
    9  = Player Duel Time Red
    10 = Player Duel Time Yellow
    12 = Spell Fusion (per user RE)

Full MSG_COMBATMOVE fields (from SendCombatMove @ FUN_14078afc0):
    MoveType         int32   action type (see enum above)
    SpellSelection   int32   card index in hand (0-based)
    SpellTarget      uint32  target subcircle bitmask
    EnchantmentID    int32   enchantment spell template ID (for enchant)
    ShadowPactTarget int32   shadow pact target
    TimeLeft         int32   planning time remaining (optional)
"""

import struct
from enum import IntEnum
from typing import List, Optional, Tuple

from loguru import logger


class MoveType(IntEnum):
    """MSG_COMBATMOVE MoveType values.

    Binary-verified from the switch in FUN_142004af0 which converts
    MoveType integers to debug strings.
    """
    CAST_SPELL = 0
    FLEE = 1
    DISCARD = 2
    PASS = 3
    UNREADY = 4
    CAST_SPECIFIC_SPELL = 5
    CAST_SPECIFIC_SPELL_WITH_PIPS = 6
    PLANNING_TIME_EXPIRED = 7
    PLAYER_DUEL_TIME_EXPIRED = 8
    PLAYER_DUEL_TIME_RED = 9
    PLAYER_DUEL_TIME_YELLOW = 10
    SPELL_FUSION = 12


class CombatActions:
    """Direct combat action injection via game messages.

    Resolves game function addresses via pattern scan of the flee
    function (FUN_140d9cda0), then builds x64 shellcode to call the
    game's message API directly from a remote thread.

    Setup and cleanup are handled automatically by HookHandler.
    End users should use the Client convenience methods::

        await client.activate_hooks()               # sets up combat actions
        await client.send_combat_pass()             # pass turn
        await client.send_combat_flee()             # flee from combat
        await client.send_combat_spell(0, 4)        # cast card 0 at subcircle 4
        await client.send_combat_enchant(1, 0)      # enchant card 0 with card 1
        await client.send_combat_discard(2)         # discard card 2 from hand
        await client.send_combat_fusion(0, 1, 4)   # fuse cards 0+1, target subcircle 4
        await client.send_combat_draw()             # draw from TC deck
        await client.send_pet_willcast("Fire Cat", 4)  # pet willcast
        await client.close()                        # frees resources
    """

    # ----------------------------------------------------------------
    # Pattern for FUN_140d9cda0 (flee / simple combat move function)
    #
    # Matches the unique prologue through the first CALL opcode:
    #   MOV [RSP+10h],RBX | PUSH RDI | SUB RSP,90h |
    #   MOV RAX,[rip+??] | XOR RAX,RSP | MOV [RSP+80h],RAX |
    #   MOV RDI,RCX | MOV EDX,10h | LEA RCX,[RSP+20h] | E8
    #
    # The .{4} wildcards cover the RIP-relative security cookie offset.
    # ----------------------------------------------------------------
    PASS_FUNC_PATTERN = (
        rb"\x48\x89\x5C\x24\x10"                   # MOV [RSP+10h], RBX
        rb"\x57"                                     # PUSH RDI
        rb"\x48\x81\xEC\x90\x00\x00\x00"           # SUB RSP, 90h
        rb"\x48\x8B\x05...."                        # MOV RAX, [rip+??]
        rb"\x48\x33\xC4"                             # XOR RAX, RSP
        rb"\x48\x89\x84\x24\x80\x00\x00\x00"       # MOV [RSP+80h], RAX
        rb"\x48\x8B\xF9"                             # MOV RDI, RCX
        rb"\xBA\x10\x00\x00\x00"                    # MOV EDX, 10h
        rb"\x48\x8D\x4C\x24\x20"                    # LEA RCX, [RSP+20h]
        rb"\xE8...."                                 # CALL msg_create (rel32)
        rb"\x90"                                     # NOP (alignment)
        rb"\x48\xC7\x44\x24\x78\x0F\x00\x00\x00"  # MOV [RSP+78h], 0Fh  (SSO cap=15)
        rb"\x48\xC7\x44\x24\x70\x0E\x00\x00\x00"  # MOV [RSP+70h], 0Eh  (SSO len=14)
        rb"\xF2\x0F\x10\x05...."                    # MOVSD XMM0, [rip+??] (load string)
        rb"\xF2\x0F\x11\x44\x24\x60"               # MOVSD [RSP+60h], XMM0
    )

    # Offset to the MOV EDX, 1 (MoveType=1) instruction.
    # Used to disambiguate when the pattern matches multiple functions.
    # At func+0xD5 the flee function has BA 01 (MOV EDX, 1) while
    # the twin function has 48 8D (LEA RDX, [RDI+offset]).
    _OFF_MOVETYPE_PROBE = 0xD5

    # Offsets from function start to E8 CALL instructions.
    # Each is a 5-byte E8 <rel32> instruction.
    _OFF_CALL_MSG_CREATE    = 0x2C   # GameMessage::Create
    _OFF_CALL_MSG_SET_TYPE  = 0x7E   # GameMessage::SetType
    _OFF_CALL_MSG_GET_FIELD = 0xD0   # GameMessage::GetField
    _OFF_CALL_MSG_SET_INT   = 0xDD   # GameMessage::SetInt32
    _OFF_CALL_MSG_SEND      = 0x127  # GameClientModules::Send
    _OFF_CALL_MSG_FREE      = 0x17B  # GameMessage::Free

    # Offsets to MOV RCX,[rip+??] instructions for global pointers.
    # Each is a 7-byte 48 8B 0D <rel32> instruction.
    _OFF_MOV_GAME_CLIENT  = 0x77   # -> DAT_143248270 (GameClient*)
    _OFF_MOV_GAME_MODULES = 0x120  # -> DAT_143248280 (GameClientModules*)

    # ----------------------------------------------------------------
    # Data block layout offsets (all 16-byte aligned)
    #
    #   +0x00: SSO "MSG_COMBATMOVE"            (32 bytes)
    #   +0x20: "MoveType\0"                    (16 bytes)
    #   +0x30: "SpellSelection\0"              (16 bytes)
    #   +0x40: "SpellTarget\0"                 (16 bytes)
    #   +0x50: "EnchantmentID\0"               (16 bytes)
    #   +0x60: "SelectedTieredSpellID\0"       (32 bytes — 22 chars)
    #   +0x80: SSO "MSG_COMBATDRAW"            (32 bytes)
    #   +0xA0: SSO "MSG_PETWILLCAST"           (32 bytes)
    #   +0xC0: "PetCastingSpell\0"             (16 bytes)
    #   +0xD0: "Target\0"                      (16 bytes)
    #   +0xE0: [64 bytes — dynamic spell name buffer for pet willcast]
    # ----------------------------------------------------------------
    _SSO_COMBATMOVE  = 0x00
    _SSO_COMBATDRAW  = 0x80
    _SSO_PETWILLCAST = 0xA0
    _FIELD_MOVE_TYPE              = 0x20
    _FIELD_SPELL_SELECTION        = 0x30
    _FIELD_SPELL_TARGET           = 0x40
    _FIELD_ENCHANTMENT_ID         = 0x50
    _FIELD_SELECTED_TIERED_SPELL  = 0x60
    _FIELD_PET_SPELL_NAME         = 0xC0
    _FIELD_TARGET                 = 0xD0
    _SPELL_NAME_BUF               = 0xE0
    _SPELL_NAME_BUF_SIZE          = 64
    _DATA_BLOCK_SIZE              = 0x120

    # Pattern for GameMessage::SetString (FUN_140360aa0).
    # Unique prologue: MOV R11,RSP | MOV [R11+10h],RBX | MOV [R11+18h],RBP |
    #   PUSH RSI | PUSH RDI | PUSH R14 | SUB RSP,70h | MOV RBP,R8
    _SET_STRING_PATTERN = (
        rb"\x4C\x8B\xDC"                # MOV R11, RSP
        rb"\x49\x89\x5B\x10"            # MOV [R11+10h], RBX
        rb"\x49\x89\x6B\x18"            # MOV [R11+18h], RBP
        rb"\x56"                         # PUSH RSI
        rb"\x57"                         # PUSH RDI
        rb"\x41\x56"                     # PUSH R14
        rb"\x48\x83\xEC\x70"            # SUB RSP, 70h
        rb"..."                          # MOV RBP, R8 (encoding varies)
    )

    # Disambiguation: at func+0x117, SetString has MOV byte ptr [RBX+30h], 9
    # which sets the field type to string (type=9).
    _SET_STRING_TYPE9_OFFSET = 0x117
    _SET_STRING_TYPE9_BYTES = b"\xC6\x43\x30\x09"

    def __init__(self, hook_handler):
        self._hh = hook_handler
        self._resolved = False

        # Resolved function addresses
        self._msg_create = 0
        self._msg_set_type = 0
        self._msg_get_field = 0
        self._msg_set_int = 0
        self._msg_set_string = 0
        self._msg_send = 0
        self._msg_free = 0

        # Resolved global pointer values
        self._game_client = 0
        self._game_modules = 0

        # Persistent data block in target process
        self._data_addr = 0

    async def setup(self):
        """Resolve all function addresses and allocate persistent data.

        Pattern scans for the flee function, then extracts all
        6 function targets from its CALL instructions and 2 global
        pointers from its MOV instructions.

        Also attempts to resolve SetString for MSG_PETWILLCAST support.
        If the SetString pattern scan fails, pet_willcast() will be
        unavailable but all other combat actions still work.

        Raises:
            PatternFailed: If the pass function pattern is not found
        """
        candidates = await self._hh.pattern_scan(
            self.PASS_FUNC_PATTERN,
            module="WizardGraphicalClient.exe",
            return_multiple=True,
        )
        if not isinstance(candidates, list):
            candidates = [candidates]

        # Disambiguate: the flee function has MOV EDX, 1 (BA 01)
        # at offset _OFF_MOVETYPE_PROBE, while twin functions use
        # LEA RDX, [RDI+offset] (48 8D) to read MoveType from a struct.
        func_addr = None
        for addr in candidates:
            probe = await self._hh.read_bytes(
                addr + self._OFF_MOVETYPE_PROBE, 2
            )
            if probe == b"\xBA\x01":
                func_addr = addr
                break

        if func_addr is None:
            from wizwalker import PatternFailed
            raise PatternFailed(
                f"Pattern matched {len(candidates)} functions but none "
                f"had MOV EDX,1 at offset +{self._OFF_MOVETYPE_PROBE:#x}"
            )

        logger.debug(f"CombatActions: flee function at {hex(func_addr)}")

        # Resolve E8 CALL targets (relative calls)
        self._msg_create = await self._resolve_call(
            func_addr + self._OFF_CALL_MSG_CREATE
        )
        self._msg_set_type = await self._resolve_call(
            func_addr + self._OFF_CALL_MSG_SET_TYPE
        )
        self._msg_get_field = await self._resolve_call(
            func_addr + self._OFF_CALL_MSG_GET_FIELD
        )
        self._msg_set_int = await self._resolve_call(
            func_addr + self._OFF_CALL_MSG_SET_INT
        )
        self._msg_send = await self._resolve_call(
            func_addr + self._OFF_CALL_MSG_SEND
        )
        self._msg_free = await self._resolve_call(
            func_addr + self._OFF_CALL_MSG_FREE
        )

        # Resolve global pointers (RIP-relative MOV -> dereference)
        self._game_client = await self._resolve_rip_ptr(
            func_addr + self._OFF_MOV_GAME_CLIENT
        )
        self._game_modules = await self._resolve_rip_ptr(
            func_addr + self._OFF_MOV_GAME_MODULES
        )

        logger.debug(
            f"CombatActions resolved: "
            f"create={hex(self._msg_create)} "
            f"set_type={hex(self._msg_set_type)} "
            f"get_field={hex(self._msg_get_field)} "
            f"set_int={hex(self._msg_set_int)} "
            f"send={hex(self._msg_send)} "
            f"free={hex(self._msg_free)} "
            f"client={hex(self._game_client)} "
            f"modules={hex(self._game_modules)}"
        )

        # Resolve SetString for MSG_PETWILLCAST (optional — failure is non-fatal)
        try:
            await self._resolve_set_string()
        except Exception as e:
            logger.warning(
                f"CombatActions: SetString resolution failed ({e}), "
                f"pet_willcast() will be unavailable"
            )

        # Allocate persistent data block with string constants
        self._data_addr = await self._hh.allocate(self._DATA_BLOCK_SIZE)
        await self._write_data_block()

        self._resolved = True
        logger.info("CombatActions: setup complete")

    async def cleanup(self):
        """Free persistent data block."""
        if self._data_addr:
            await self._hh.free(self._data_addr)
            self._data_addr = 0
        self._resolved = False

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    async def pass_turn(self):
        """Send a pass action for the current combat turn.

        Uses MoveType=3 (Pass) — skip turn, stay in combat.
        Note: MoveType=1 (Flee) leaves combat entirely.
        """
        await self._send_combat_move(
            move_type=MoveType.PASS, spell_selection=0, spell_target=0
        )

    async def flee(self):
        """Flee from combat entirely.

        Uses MoveType=1 (Flee) — leaves the battle.
        """
        await self._send_combat_move(
            move_type=MoveType.FLEE, spell_selection=0, spell_target=0
        )

    async def cast_spell(self, hand_index: int, target_subcircle: int):
        """Send a spell cast action.

        Args:
            hand_index: Index of the spell card in the player's hand
                (0-based, left to right)
            target_subcircle: Target subcircle index (0-7)
        """
        await self._send_combat_move(
            move_type=MoveType.CAST_SPELL,
            spell_selection=hand_index,
            spell_target=target_subcircle,
        )

    async def enchant_spell(
        self,
        enchant_index: int,
        target_index: int,
    ):
        """Apply an enchantment card to a spell card in hand.

        Uses MoveType=0 (CAST_SPELL) with SpellSelection=enchant card
        and SpellTarget=target card. The server resolves the enchantment
        from the card indices.

        Args:
            enchant_index: Index of the enchant card in hand
            target_index: Index of the spell card to enchant
        """
        await self._send_combat_move(
            move_type=MoveType.CAST_SPELL,
            spell_selection=enchant_index,
            spell_target=target_index,
        )

    async def fuse_spells(
        self,
        primary_index: int,
        secondary_index: int,
        fused_spell_id: int = 0,
    ):
        """Fuse two spell cards together (spell fusion).

        MoveType=12 with SpellSelection=primary card, SpellTarget=secondary
        card, and SelectedTieredSpellID=the resulting fused spell template ID.

        Args:
            primary_index: Index of the primary spell card in hand
            secondary_index: Index of the secondary spell card in hand
            fused_spell_id: Template ID of the resulting fused spell
                (0 to let the server resolve it)
        """
        await self._send_combat_move(
            move_type=MoveType.SPELL_FUSION,
            spell_selection=primary_index,
            spell_target=secondary_index,
            selected_tiered_spell_id=fused_spell_id,
        )

    async def discard_card(self, hand_index: int):
        """Discard a card from hand.

        Args:
            hand_index: Index of the card to discard
        """
        await self._send_combat_move(
            move_type=MoveType.DISCARD,
            spell_selection=hand_index,
            spell_target=0,
        )

    async def draw_card(self):
        """Draw a treasure card from the TC deck.

        Sends MSG_COMBATDRAW with no fields — the message type alone
        triggers the draw action.
        """
        await self._send_message(self._SSO_COMBATDRAW)

    async def pet_willcast(self, spell_name: str, target: int):
        """Trigger a pet may-cast spell.

        Sends MSG_PETWILLCAST with the spell name as a string field
        and the target subcircle as an int field.

        Args:
            spell_name: Name of the pet spell to cast (e.g. "Fire Cat")
            target: Target subcircle index (0-7)

        Raises:
            RuntimeError: If SetString was not resolved during setup
        """
        if self._msg_set_string == 0:
            raise RuntimeError(
                "SetString not resolved — pet_willcast() is unavailable. "
                "Check logs from setup() for the pattern scan error."
            )

        # Write spell name to the dynamic buffer in the data block
        name_bytes = spell_name.encode("ascii")
        if len(name_bytes) >= self._SPELL_NAME_BUF_SIZE:
            raise ValueError(
                f"Spell name too long ({len(name_bytes)} bytes, "
                f"max {self._SPELL_NAME_BUF_SIZE - 1})"
            )
        # Write null-terminated string, zero-pad the rest
        buf = name_bytes + b"\x00" * (self._SPELL_NAME_BUF_SIZE - len(name_bytes))
        await self._hh.write_bytes(
            self._data_addr + self._SPELL_NAME_BUF, buf
        )

        await self._send_message(
            self._SSO_PETWILLCAST,
            int_fields=[(self._FIELD_TARGET, target)],
            str_fields=[(self._FIELD_PET_SPELL_NAME, self._SPELL_NAME_BUF)],
        )

    async def send_raw(
        self,
        move_type: int,
        spell_selection: int = 0,
        spell_target: int = 0,
        enchantment_id: int = 0,
    ):
        """Send an arbitrary MSG_COMBATMOVE with custom field values.

        Use this for testing new move types or field combinations.

        Args:
            move_type: MoveType value (see MoveType enum)
            spell_selection: SpellSelection field value
            spell_target: SpellTarget field value
            enchantment_id: EnchantmentID field value (0 to omit)
        """
        await self._send_combat_move(
            move_type=move_type,
            spell_selection=spell_selection,
            spell_target=spell_target,
            enchantment_id=enchantment_id,
        )

    # ----------------------------------------------------------------
    # Internal: send messages
    # ----------------------------------------------------------------

    async def _send_combat_move(
        self,
        move_type: int,
        spell_selection: int,
        spell_target: int,
        enchantment_id: int = 0,
        selected_tiered_spell_id: int = 0,
    ):
        """Build and execute shellcode to send MSG_COMBATMOVE."""
        fields = [
            (self._FIELD_MOVE_TYPE, move_type),
            (self._FIELD_SPELL_SELECTION, spell_selection),
            (self._FIELD_SPELL_TARGET, spell_target),
        ]
        if enchantment_id != 0:
            fields.append((self._FIELD_ENCHANTMENT_ID, enchantment_id))
        if selected_tiered_spell_id != 0:
            fields.append((self._FIELD_SELECTED_TIERED_SPELL, selected_tiered_spell_id))
        await self._send_message(self._SSO_COMBATMOVE, int_fields=fields)

    async def _send_message(
        self,
        sso_offset: int,
        int_fields: Optional[List[Tuple[int, int]]] = None,
        str_fields: Optional[List[Tuple[int, int]]] = None,
    ):
        """Build and execute shellcode to send a game message.

        Args:
            sso_offset: Offset into data block of the SSO message type string
            int_fields: List of (field_name_offset, value) for int32 fields
            str_fields: List of (field_name_offset, string_data_offset) for
                string fields (data_offset is relative to data block start)
        """
        if not self._resolved:
            raise RuntimeError(
                "CombatActions not initialized. Call setup() first."
            )

        shellcode = self._build_message_shellcode(
            sso_offset,
            int_fields=int_fields or [],
            str_fields=str_fields or [],
        )
        shell_ptr = await self._hh.allocate(len(shellcode))
        await self._hh.write_bytes(shell_ptr, shellcode)
        await self._hh.start_thread(shell_ptr)
        # start_thread waits for thread completion, safe to free
        await self._hh.free(shell_ptr)

    # ----------------------------------------------------------------
    # Address resolution helpers
    # ----------------------------------------------------------------

    async def _resolve_call(self, call_addr: int) -> int:
        """Resolve an E8 relative CALL to an absolute address.

        An E8 CALL instruction is 5 bytes: E8 <rel32>.
        Target = call_addr + 5 + signed_rel32
        """
        rel32_bytes = await self._hh.read_bytes(call_addr + 1, 4)
        rel32 = struct.unpack("<i", rel32_bytes)[0]
        return call_addr + 5 + rel32

    async def _resolve_rip_ptr(self, mov_addr: int) -> int:
        """Resolve MOV reg,[rip+offset] and read the pointer value.

        Instruction format: 48 8B 0D/05 <rel32> (7 bytes total).
        The RIP value at execution time = mov_addr + 7 (end of instr).
        Target address = (mov_addr + 7) + rel32
        We then read the 8-byte pointer stored at that address.
        """
        rel32_bytes = await self._hh.read_bytes(mov_addr + 3, 4)
        rel32 = struct.unpack("<i", rel32_bytes)[0]
        target_addr = mov_addr + 7 + rel32
        ptr_bytes = await self._hh.read_bytes(target_addr, 8)
        return struct.unpack("<Q", ptr_bytes)[0]

    async def _resolve_set_string(self):
        """Resolve GameMessage::SetString via pattern scan.

        SetString (FUN_140360aa0) has a unique prologue that we scan for.
        If multiple matches, we disambiguate by checking for
        MOV byte ptr [RBX+30h], 9 at offset +0x117 (sets field type=string).
        """
        candidates = await self._hh.pattern_scan(
            self._SET_STRING_PATTERN,
            module="WizardGraphicalClient.exe",
            return_multiple=True,
        )
        if not isinstance(candidates, list):
            candidates = [candidates]

        logger.debug(
            f"CombatActions: SetString pattern matched {len(candidates)} "
            f"candidate(s): {[hex(a) for a in candidates]}"
        )

        for addr in candidates:
            probe = await self._hh.read_bytes(
                addr + self._SET_STRING_TYPE9_OFFSET,
                len(self._SET_STRING_TYPE9_BYTES),
            )
            if probe == self._SET_STRING_TYPE9_BYTES:
                self._msg_set_string = addr
                logger.debug(f"CombatActions: SetString at {hex(addr)}")
                return

        # If only one match, use it without disambiguation
        if len(candidates) == 1:
            self._msg_set_string = candidates[0]
            logger.debug(
                f"CombatActions: SetString at {hex(candidates[0])} "
                f"(single match, no disambiguation needed)"
            )
            return

        from wizwalker import PatternFailed
        raise PatternFailed(
            f"SetString pattern matched {len(candidates)} functions but none "
            f"had type=9 marker at offset +{self._SET_STRING_TYPE9_OFFSET:#x}"
        )

    # ----------------------------------------------------------------
    # Persistent data block
    # ----------------------------------------------------------------

    async def _write_data_block(self):
        """Write string constants to the persistent data block.

        Layout (all 16-byte aligned):
          +0x00: SSO "MSG_COMBATMOVE"    (32 bytes)
          +0x20: "MoveType\\0"            (16 bytes)
          +0x30: "SpellSelection\\0"      (16 bytes)
          +0x40: "SpellTarget\\0"         (16 bytes)
          +0x50: "EnchantmentID\\0"       (16 bytes)
          +0x60: SSO "MSG_COMBATDRAW"    (32 bytes)
          +0x80: SSO "MSG_PETWILLCAST"   (32 bytes)
          +0xA0: "PetCastingSpell\\0"    (16 bytes)
          +0xB0: "Target\\0"             (16 bytes)
          +0xC0: [64 bytes reserved — dynamic spell name buffer]

        SSO strings use MSVC's small-string optimization layout:
        when size <= 15, the characters are stored inline (no heap
        alloc), so the data block is safe to reuse without cleanup.
        """
        data = bytearray(self._DATA_BLOCK_SIZE)

        # SSO message type strings
        self._write_sso(data, self._SSO_COMBATMOVE, b"MSG_COMBATMOVE")
        self._write_sso(data, self._SSO_COMBATDRAW, b"MSG_COMBATDRAW")
        self._write_sso(data, self._SSO_PETWILLCAST, b"MSG_PETWILLCAST")

        # C strings for field names
        self._write_cstr(data, self._FIELD_MOVE_TYPE, b"MoveType")
        self._write_cstr(data, self._FIELD_SPELL_SELECTION, b"SpellSelection")
        self._write_cstr(data, self._FIELD_SPELL_TARGET, b"SpellTarget")
        self._write_cstr(data, self._FIELD_ENCHANTMENT_ID, b"EnchantmentID")
        self._write_cstr(data, self._FIELD_SELECTED_TIERED_SPELL, b"SelectedTieredSpellID")
        self._write_cstr(data, self._FIELD_PET_SPELL_NAME, b"PetCastingSpell")
        self._write_cstr(data, self._FIELD_TARGET, b"Target")

        await self._hh.write_bytes(self._data_addr, bytes(data))

    @staticmethod
    def _write_sso(data: bytearray, offset: int, text: bytes):
        """Write an MSVC SSO std::string into the data block.

        Layout (32 bytes total):
          +0x00: inline buffer (16 bytes, null-padded)
          +0x10: size  (uint64)
          +0x18: capacity (uint64) — always 15 for SSO
        """
        buf = text + b"\x00" * (16 - len(text))
        data[offset:offset + 16] = buf
        struct.pack_into("<Q", data, offset + 0x10, len(text))
        struct.pack_into("<Q", data, offset + 0x18, 15)

    @staticmethod
    def _write_cstr(data: bytearray, offset: int, text: bytes):
        """Write a null-terminated C string into a 16-byte slot."""
        cstr = text + b"\x00"
        data[offset:offset + len(cstr)] = cstr

    # ----------------------------------------------------------------
    # Shellcode generation
    # ----------------------------------------------------------------

    def _build_message_shellcode(
        self,
        sso_offset: int,
        int_fields: List[Tuple[int, int]],
        str_fields: List[Tuple[int, int]],
    ) -> bytes:
        """Generate x64 shellcode to send a game message.

        Follows the same injection pattern as Client._switch_camera():
        allocate -> write shellcode -> start_thread -> free.

        Microsoft x64 ABI:
          - First 4 integer args: RCX, RDX, R8, R9
          - 32-byte shadow space before every CALL
          - Stack 16-byte aligned at CALL instruction

        Stack layout after SUB RSP, 0x88:
          [RSP+0x00..0x1F]: 32-byte shadow space for callees
          [RSP+0x20..0x5F]: 64-byte message buffer

        CreateRemoteThread enters with RSP 8-misaligned (return addr
        was pushed). SUB RSP, 0x88 (0x88 mod 16 = 8) restores
        16-byte alignment before each CALL instruction.

        Args:
            sso_offset: Offset into data block of the SSO string
            int_fields: List of (field_name_offset, value) for SetInt32
            str_fields: List of (field_name_offset, string_data_offset)
                for SetString (data_offset relative to data block start)
        """
        q = lambda addr: struct.pack("<Q", addr)  # 8-byte absolute addr
        da = self._data_addr

        # fmt: off
        shellcode = (
            # -- Prologue: allocate stack frame --
            b"\x48\x81\xEC\x88\x00\x00\x00"         # sub rsp, 0x88

            # -- GameMessage::Create(buf, 0x10) --
            b"\x48\x8D\x4C\x24\x20"                  # lea rcx, [rsp+0x20]
            b"\xBA\x10\x00\x00\x00"                   # mov edx, 0x10
            b"\x48\xB8" + q(self._msg_create) +       # mov rax, <msg_create>
            b"\xFF\xD0"                                # call rax

            # -- GameMessage::SetType(game_client, buf, &sso) --
            b"\x48\xB9" + q(self._game_client) +      # mov rcx, <game_client>
            b"\x48\x8D\x54\x24\x20"                   # lea rdx, [rsp+0x20]
            b"\x49\xB8" + q(da + sso_offset) +        # mov r8, <&sso_string>
            b"\x48\xB8" + q(self._msg_set_type) +     # mov rax, <msg_set_type>
            b"\xFF\xD0"                                # call rax
        )

        # -- Set int32 fields --
        for field_offset, value in int_fields:
            shellcode += (
                b"\x48\x8D\x4C\x24\x20"                   # lea rcx, [rsp+0x20]
                b"\x48\xBA" + q(da + field_offset) +       # mov rdx, <field_name>
                b"\x48\xB8" + q(self._msg_get_field) +     # mov rax, <get_field>
                b"\xFF\xD0"                                 # call rax
                b"\x48\x89\xC1"                             # mov rcx, rax (field)
                b"\xBA" + struct.pack("<I", value) +        # mov edx, <value>
                b"\x48\xB8" + q(self._msg_set_int) +       # mov rax, <set_int>
                b"\xFF\xD0"                                 # call rax
            )

        # -- Set string fields --
        for field_offset, string_data_offset in str_fields:
            shellcode += (
                b"\x48\x8D\x4C\x24\x20"                   # lea rcx, [rsp+0x20]
                b"\x48\xBA" + q(da + field_offset) +       # mov rdx, <field_name>
                b"\x48\xB8" + q(self._msg_get_field) +     # mov rax, <get_field>
                b"\xFF\xD0"                                 # call rax
                b"\x48\x89\xC1"                             # mov rcx, rax (field)
                b"\x48\xBA" + q(da + string_data_offset) + # mov rdx, <string_ptr>
                b"\x45\x31\xC0"                             # xor r8d, r8d (len=0, auto)
                b"\x48\xB8" + q(self._msg_set_string) +    # mov rax, <set_string>
                b"\xFF\xD0"                                 # call rax
            )

        shellcode += (
            # -- GameClientModules::Send(modules, buf, 0) --
            b"\x48\xB9" + q(self._game_modules) +     # mov rcx, <game_modules>
            b"\x48\x8D\x54\x24\x20"                   # lea rdx, [rsp+0x20]
            b"\x45\x31\xC0"                            # xor r8d, r8d
            b"\x48\xB8" + q(self._msg_send) +         # mov rax, <msg_send>
            b"\xFF\xD0"                                # call rax

            # -- GameMessage::Free(buf) --
            b"\x48\x8D\x4C\x24\x20"                   # lea rcx, [rsp+0x20]
            b"\x48\xB8" + q(self._msg_free) +         # mov rax, <msg_free>
            b"\xFF\xD0"                                # call rax

            # -- Epilogue --
            b"\x48\x81\xC4\x88\x00\x00\x00"           # add rsp, 0x88
            b"\xC3"                                     # ret
        )
        # fmt: on

        return shellcode
