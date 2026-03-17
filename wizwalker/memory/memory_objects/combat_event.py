from typing import List

from wizwalker.memory.memory_object import Primitive, PropertyClass, DynamicMemoryObject


class CombatEvent(PropertyClass):
    """
    Memory object for CombatEvent structs in the game's combat event list.

    Binary-verified offsets from CombatEvent__ConstructWithParams (0x14034dd80).
    The event list is a std::list<CombatEvent> stored at CombatResolver offsets
    +0x50 (sentinel) and +0x58 (count). Each list node is 0xF0 bytes:
    0x10 (next/prev ptrs) + 0xE0 (CombatEvent data).
    """

    async def read_base_address(self) -> int:
        raise NotImplementedError()

    # --- event_type (offset 0x48 = 72) ---
    async def event_type(self) -> int:
        """Event type ID. Type 0x6F is filtered and never stored in the list."""
        return await self.read_value_from_offset(72, Primitive.int32)

    async def write_event_type(self, event_type: int):
        await self.write_value_to_offset(72, event_type, Primitive.int32)

    # --- source_subcircle (offset 0x4C = 76) ---
    async def source_subcircle(self) -> int:
        """Source combat position (subcircle index)."""
        return await self.read_value_from_offset(76, Primitive.int32)

    async def write_source_subcircle(self, source_subcircle: int):
        await self.write_value_to_offset(76, source_subcircle, Primitive.int32)

    # --- target_subcircle (offset 0x50 = 80) ---
    async def target_subcircle(self) -> int:
        """Target combat position (subcircle index)."""
        return await self.read_value_from_offset(80, Primitive.int32)

    async def write_target_subcircle(self, target_subcircle: int):
        await self.write_value_to_offset(80, target_subcircle, Primitive.int32)

    # --- effect_param (offset 0x54 = 84) ---
    async def effect_param(self) -> int:
        """Effect-specific parameter (stat-modified from XML m_effectParam).

        For damage/heal events this is the actual amount. For hanging
        effects this is the buff/debuff strength. Note: the value has
        already been modified by equipment stats at runtime (e.g. a
        HealOverTime XML param of 250 becomes 252 with +0.8% outgoing
        heal stat, via ApplyEquipmentEffectCharms in CombatResolver).
        """
        return await self.read_value_from_offset(84, Primitive.int32)

    async def write_effect_param(self, effect_param: int):
        await self.write_value_to_offset(84, effect_param, Primitive.int32)

    # --- effect_type (offset 0x58 = 88) ---
    async def effect_type(self) -> int:
        """Spell template ID (NOT SpellEffect::kSpellEffects enum).

        This field holds the spell's template hash (e.g. 877257192 for
        Aeon_Poly03_Spell_02), not the spell effect category.
        """
        return await self.read_value_from_offset(88, Primitive.int32)

    async def write_effect_type(self, effect_type: int):
        await self.write_value_to_offset(88, effect_type, Primitive.int32)

    # --- effect_value (offset 0x60 = 96) ---
    async def effect_value(self) -> int:
        """Primary effect value."""
        return await self.read_value_from_offset(96, Primitive.int32)

    async def write_effect_value(self, effect_value: int):
        await self.write_value_to_offset(96, effect_value, Primitive.int32)

    # --- success_flag (offset 0x64 = 100) ---
    async def success_flag(self) -> bool:
        """Whether the effect succeeded."""
        return await self.read_value_from_offset(100, Primitive.bool)

    async def write_success_flag(self, success_flag: bool):
        await self.write_value_to_offset(100, success_flag, Primitive.bool)

    # --- damage_or_heal (offset 0x68 = 104) ---
    async def damage_or_heal(self) -> int:
        """School hash for the effect (e.g. 2330892=Life, 78318724=Death).

        Despite the field name, observed values are school hashes, not
        damage amounts. The actual damage/heal amount is in effect_param.
        """
        return await self.read_value_from_offset(104, Primitive.int32)

    async def write_damage_or_heal(self, damage_or_heal: int):
        await self.write_value_to_offset(104, damage_or_heal, Primitive.int32)

    # --- secondary_value (offset 0x6C = 108) ---
    async def secondary_value(self) -> int:
        """Secondary value (resist amount, etc)."""
        return await self.read_value_from_offset(108, Primitive.int32)

    async def write_secondary_value(self, secondary_value: int):
        await self.write_value_to_offset(108, secondary_value, Primitive.int32)

    # --- critical_flag (offset 0x74 = 116) ---
    async def critical_flag(self) -> bool:
        """Whether this was a critical hit."""
        return await self.read_value_from_offset(116, Primitive.bool)

    async def write_critical_flag(self, critical_flag: bool):
        await self.write_value_to_offset(116, critical_flag, Primitive.bool)

    # --- school (offset 0x78 = 120) ---
    async def school(self) -> int:
        """Unknown small integer (not a school hash).

        Observed values: 1, 8, 9, 11. Purpose not yet identified —
        possibly effect disposition, application index, or subcategory.
        """
        return await self.read_value_from_offset(120, Primitive.int32)

    async def write_school(self, school: int):
        await self.write_value_to_offset(120, school, Primitive.int32)

    # --- caster_name (offset 0x80 = 128, SSO std::string, 32 bytes) ---
    async def caster_name(self) -> str:
        """Caster name string (SSO std::string at +0x80).

        Notes:
            ResolveCombatRound passes empty strings for both caster/target
            names (verified: DAT_142cd867f and DAT_142cd86d2 are null
            terminators). Use source_subcircle/target_subcircle with the
            Duel participant list to identify participants instead.
        """
        return await self.read_string_from_offset(128)

    async def write_caster_name(self, caster_name: str):
        await self.write_string_to_offset(128, caster_name)

    # --- target_name (offset 0xA0 = 160, SSO std::string, 32 bytes) ---
    async def target_name(self) -> str:
        """Target name string (SSO std::string at +0xA0)."""
        return await self.read_string_from_offset(160)

    async def write_target_name(self, target_name: str):
        await self.write_string_to_offset(160, target_name)

    # --- pip_info_1 (offset 0xC0 = 192) ---
    async def pip_info_1(self) -> int:
        """Pip info field 1 (initialized to 0)."""
        return await self.read_value_from_offset(192, Primitive.int32)

    async def write_pip_info_1(self, pip_info_1: int):
        await self.write_value_to_offset(192, pip_info_1, Primitive.int32)

    # --- pip_flag_1 (offset 0xC4 = 196) ---
    async def pip_flag_1(self) -> bool:
        """Pip flag 1 (initialized to 0)."""
        return await self.read_value_from_offset(196, Primitive.bool)

    async def write_pip_flag_1(self, pip_flag_1: bool):
        await self.write_value_to_offset(196, pip_flag_1, Primitive.bool)

    # --- pip_info_2 (offset 0xC8 = 200) ---
    async def pip_info_2(self) -> int:
        """Pip info field 2 (initialized to -1)."""
        return await self.read_value_from_offset(200, Primitive.int32)

    async def write_pip_info_2(self, pip_info_2: int):
        await self.write_value_to_offset(200, pip_info_2, Primitive.int32)

    # --- pip_flag_2 (offset 0xCC = 204) ---
    async def pip_flag_2(self) -> bool:
        """Pip flag 2 (initialized to 0)."""
        return await self.read_value_from_offset(204, Primitive.bool)

    async def write_pip_flag_2(self, pip_flag_2: bool):
        await self.write_value_to_offset(204, pip_flag_2, Primitive.bool)


class DynamicCombatEvent(DynamicMemoryObject, CombatEvent):
    pass
