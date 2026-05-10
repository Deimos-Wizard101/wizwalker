"""
Test script: save deck to JSON, clear it, then restore it.

Prerequisites:
  - Wizard101 must be running
  - Character must be in a safe location (not in combat)

Usage:
  py test_deck_save_load.py
  py test_deck_save_load.py --save-path my_deck.json
"""

import asyncio
import argparse
import json
import sys
from pathlib import Path

# Use the local repo rather than the installed package
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wizwalker import ClientHandler
from wizwalker.extensions.scripting.deck_builder import DeckBuilder

DEFAULT_SAVE_PATH = Path("deck_backup.json")


async def main(save_path: Path):
    handler = ClientHandler()
    clients = handler.get_new_clients()
    if not clients:
        print("No Wizard101 client found. Start the game first.")
        return

    client = clients[0]

    try:
        print("Activating hooks...")
        await client.activate_hooks()
        print("Ready.\n")

        async with DeckBuilder(client) as db:
            # --- Step 1: Save ---
            print("Step 1: Reading current deck...")
            preset = await db.get_deck_preset()

            normal_total = sum(preset["normal"].values())
            tc_total     = sum(preset["tc"].values())
            item_total   = sum(preset["item"].values())
            print(f"  Normal cards : {normal_total} ({len(preset['normal'])} unique)")
            print(f"  Treasure cards: {tc_total} ({len(preset['tc'])} unique)")
            print(f"  Item cards   : {item_total} ({len(preset['item'])} unique)")

            save_path.write_text(json.dumps(preset, indent=2))
            print(f"\n  Saved to {save_path.resolve()}\n")

            # --- Step 2: Clear ---
            print("Step 2: Clearing deck...")
            await db.clear_full_deck()
            print("  Done.\n")

            # --- Step 3: Verify clear ---
            print("Step 3: Verifying deck is empty...")
            await db.refresh_deck_page()
            count_after_clear = await db.get_deck_count()
            if count_after_clear != 0:
                print(f"  WARNING: deck still shows {count_after_clear} card(s) after clear.")
            else:
                print("  Deck is empty. OK\n")

            # --- Step 4: Debug spell list ---
            loaded = json.loads(save_path.read_text())
            print("Step 4: Dumping available spell list...")
            spell_entries = await db.get_spell_list()
            available = []
            for entry in spell_entries:
                try:
                    gfx = await entry.graphical_spell()
                    if not gfx:
                        continue
                    tmpl = await gfx.spell_template()
                    if not tmpl:
                        continue
                    available.append(await tmpl.name())
                except Exception:
                    pass
            print(f"  {len(available)} spells visible in SpellList:")
            for name in available:
                print(f"    {name}")

            wanted = set(loaded["normal"].keys()) | set(loaded["tc"].keys())
            missing = wanted - set(available)
            if missing:
                print(f"\n  Cards in preset NOT found in spell list:")
                for name in sorted(missing):
                    print(f"    MISSING: {name}")
            else:
                print("\n  All preset cards found in spell list. OK")
            print()

            # --- Step 5: Restore ---
            print("Step 5: Restoring deck from saved preset...")
            await db.set_deck_preset(loaded)
            print("  Done.\n")

            # --- Step 6: Verify restore ---
            print("Step 6: Verifying restored deck...")
            await db.refresh_deck_page()
            restored = await db.get_deck_preset()

            mismatches = []
            for section in ("normal", "tc", "item"):
                orig = preset[section]
                rest = restored[section]
                for name, count in orig.items():
                    if rest.get(name, 0) != count:
                        mismatches.append(
                            f"  {section}/{name}: expected {count}, got {rest.get(name, 0)}"
                        )
                for name in rest:
                    if name not in orig:
                        mismatches.append(
                            f"  {section}/{name}: unexpected card in restored deck"
                        )

            if mismatches:
                print("  FAIL — mismatches found:")
                for m in mismatches:
                    print(m)
            else:
                restored_normal = sum(restored["normal"].values())
                restored_tc     = sum(restored["tc"].values())
                restored_item   = sum(restored["item"].values())
                print(f"  Normal cards : {restored_normal} (expected {normal_total})")
                print(f"  Treasure cards: {restored_tc} (expected {tc_total})")
                print(f"  Item cards   : {restored_item} (expected {item_total})")
                print("\n  PASS — deck restored successfully.")

    finally:
        print("\nClosing...")
        await handler.close()
        print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Save, clear, and restore a Wizard101 deck.")
    parser.add_argument(
        "--save-path", type=Path, default=DEFAULT_SAVE_PATH,
        help=f"Path to write the deck JSON (default: {DEFAULT_SAVE_PATH})",
    )
    args = parser.parse_args()
    asyncio.run(main(args.save_path))
