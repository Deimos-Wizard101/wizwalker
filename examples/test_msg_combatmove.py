"""Combat Action Test TUI — interactively test all combat message types.

Connects to the first Wizard101 client, activates hooks, then presents
a menu to send individual combat actions. Must be in combat for most
actions to have visible effect.

Usage:
    python examples/auto_combat.py
"""

import asyncio
import sys

from loguru import logger

from wizwalker import ClientHandler


def print_menu():
    print("\n" + "=" * 50)
    print("  Combat Action Test Menu")
    print("=" * 50)
    print("  1) Pass turn")
    print("  2) Flee")
    print("  3) Cast spell")
    print("  4) Enchant spell")
    print("  5) Discard card")
    print("  6) Spell fusion")
    print("  7) Draw TC")
    print("  8) Pet willcast")
    print("  p) Show participants")
    print("  q) Quit")
    print("=" * 50)


def prompt_int(label: str, default: int) -> int:
    raw = input(f"  {label} [{default}]: ").strip()
    if not raw:
        return default
    return int(raw)


def prompt_str(label: str, default: str) -> str:
    raw = input(f"  {label} [{default}]: ").strip()
    return raw if raw else default


async def show_participants(client):
    """Print combat participants with subcircle indices."""
    try:
        in_battle = await client.in_battle()
    except Exception:
        in_battle = False

    if not in_battle:
        print("  Not in combat.")
        return

    try:
        participants = await client.duel.participant_list()
    except Exception as e:
        print(f"  Could not read participants: {e}")
        return

    # Get our own global ID to identify "me"
    my_id = await client.client_object.global_id_full()
    my_part = None

    print()
    for i, part in enumerate(participants):
        try:
            owner_id = await part.owner_id_full()
            is_player = await part.is_player()
            team = await part.team_id()
            sub = await part.subcircle()
            hp = await part.player_health()
            max_hp = await part.max_player_health()
            is_me = owner_id == my_id
            if is_me:
                my_part = part

            name = "???"
            try:
                entity = await part.fetch_entity()
                if entity:
                    name = await entity.display_name() or "???"
            except Exception:
                pass

            kind = "Player" if is_player else "Mob"
            tag = " <-- YOU" if is_me else ""
            print(
                f"  [{i}] sub={sub}  team={team}  {kind:6s}  "
                f"{name:20s}  HP={hp}/{max_hp}{tag}"
            )
        except Exception as e:
            print(f"  [{i}] Error: {e}")

    # Show cards in hand
    if my_part:
        print("\n  --- Your Hand ---")
        try:
            hand = await my_part.hand()
            if hand is None:
                print("  (no hand)")
            else:
                spells = await hand.spell_list()
                if not spells:
                    print("  (empty)")
                else:
                    for idx, spell in enumerate(spells):
                        try:
                            template = await spell.spell_template()
                            name = await template.name() if template else "???"
                            tid = await spell.template_id()
                        except Exception:
                            name = "???"
                            tid = 0
                        print(f"  [{idx}] {name:30s}  (id={tid})")
        except Exception as e:
            print(f"  Could not read hand: {e}")


async def run_action(client, choice: str):
    if choice == "p":
        await show_participants(client)
        return

    if choice == "1":
        print("  -> Sending pass...")
        await client.send_combat_pass()

    elif choice == "2":
        print("  -> Sending flee...")
        await client.send_combat_flee()

    elif choice == "3":
        hand_index = prompt_int("Hand index", 0)
        target = prompt_int("Target subcircle", 4)
        print(f"  -> Casting spell (hand={hand_index}, target={target})...")
        await client.send_combat_spell(hand_index, target)

    elif choice == "4":
        enchant_index = prompt_int("Enchant card index", 1)
        target_index = prompt_int("Target card index", 0)
        print(
            f"  -> Enchanting (enchant={enchant_index}, "
            f"target={target_index})..."
        )
        await client.send_combat_enchant(enchant_index, target_index)

    elif choice == "5":
        hand_index = prompt_int("Hand index", 2)
        print(f"  -> Discarding card {hand_index}...")
        await client.send_combat_discard(hand_index)

    elif choice == "6":
        primary = prompt_int("Primary card index", 0)
        secondary = prompt_int("Secondary card index", 1)
        fused_id = prompt_int("Fused spell ID (0=auto)", 0)
        print(
            f"  -> Fusing (primary={primary}, "
            f"secondary={secondary}, fused_id={fused_id})..."
        )
        await client.send_combat_fusion(primary, secondary, fused_id)

    elif choice == "7":
        print("  -> Drawing TC...")
        await client.send_combat_draw()

    elif choice == "8":
        spell_name = prompt_str("Spell name", "Fire Cat")
        target = prompt_int("Target subcircle", 4)
        print(f"  -> Pet willcast ({spell_name}, target={target})...")
        await client.send_pet_willcast(spell_name, target)

    else:
        print("  Unknown option.")
        return

    print("  Done.")


async def main():
    handler = ClientHandler()
    clients = handler.get_new_clients()
    if not clients:
        print("No Wizard101 clients found.")
        return

    client = clients[0]
    print(f"Connected to client (pid={client.process_id})")

    try:
        print("Activating hooks...")
        await client.activate_hooks()
        print("Ready. Enter combat and select an action.\n")

        while True:
            print_menu()
            choice = input("  Select: ").strip().lower()
            if choice == "q":
                break
            try:
                await run_action(client, choice)
            except Exception as e:
                logger.error(f"Action failed: {e}")

    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        print("Closing...")
        await handler.close()


if __name__ == "__main__":
    asyncio.run(main())
