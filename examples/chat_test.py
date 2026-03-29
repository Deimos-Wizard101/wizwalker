"""Chat test CLI.

Run on 2 game clients. Use option 1 to get each client's GID,
then use option 2 on one client to send a whisper to the other.

Sending uses the GameClient (already hooked via ClientHook) —
no ChatHook needed. ChatHook is only for reading incoming messages.

Controls:
  1      - Print your character's GID
  2      - Send a directed chat message to a target GID
  Ctrl+C - Unhook cleanly and exit
"""

import asyncio

from wizwalker import ClientHandler


async def main():
    handler = ClientHandler()
    clients = handler.get_new_clients()
    if not clients:
        print("No game clients found. Launch Wizard101 first.")
        return

    client = clients[0]
    print(f"Attached to client (PID: {client._pymem.process_id})")

    try:
        print("Activating hooks...")
        await client.activate_hooks()

        print("Activating chat send hook (main-thread send)...")
        await client.hook_handler.activate_chat_send_hook()

        print("\n=== Chat Test CLI ===")
        print("  1      - Get your GID")
        print("  2      - Send directed chat to a GID")
        print("  Ctrl+C - Exit\n")

        while True:
            choice = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input("> ").strip()
            )

            if choice == "1":
                gid = await client.game_client.player_gid()
                print(f"  Your GID: {gid}")

            elif choice == "2":
                target_str = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("  Target GID: ").strip()
                )
                try:
                    target_gid = int(target_str)
                except ValueError:
                    print("  Invalid GID")
                    continue

                msg = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("  Message: ").strip()
                )
                if not msg:
                    print("  Empty message")
                    continue

                print(f"  Sending to {target_gid}: {msg!r}")
                try:
                    await client.chat_owner.send_msg(msg, target_gid=target_gid)
                    print("  Sent!")
                except Exception as e:
                    print(f"  Send failed: {e}")

            else:
                print("  Unknown option. Use 1, 2, or Ctrl+C.")

    except KeyboardInterrupt:
        print("\nCtrl+C received")
    finally:
        print("Unhooking...")
        try:
            await client.hook_handler.deactivate_chat_send_hook()
        except Exception:
            pass
        await handler.close()
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
