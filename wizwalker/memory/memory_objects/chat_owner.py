import asyncio
import struct

from wizwalker.memory.memory_object import MemoryObject, DynamicMemoryObject
from wizwalker.constants import Primitive


# DirectedChatRequest struct layout (param_2 of FUN_1416e5ac0):
#
# MSVC x64 std::wstring (32 bytes) + target GID (8 bytes) = 40 bytes
#
#   0x00  union { wchar_t buf[8]; wchar_t* ptr; }  (16 bytes)
#   0x10  uint64 size       (wchar count)
#   0x18  uint64 capacity   (<=7 means SSO inline, >7 means heap ptr at 0x00)
#   0x20  uint64 target_id  (GID)
_STRUCT_SIZE = 0x28
_MAX_SSO_WCHARS = 7


class ChatOwner(MemoryObject):
    """The chat module object captured by ChatHook.

    Provides send_msg() to whisper another player. The send executes
    on the game's main thread via ChatSendHook, which calls the game's
    own FUN_1416e5ac0 — keeping all validation, filtering, buddy checks,
    and UI updates intact.
    """

    async def read_base_address(self) -> int:
        raise NotImplementedError()

    async def send_msg(self, message: str, target_gid: int):
        """Send a directed chat (whisper) to a player.

        The message is written to the ChatSendHook's export buffer,
        then a trigger flag is set. The hook (running on the game's
        main thread each frame) picks it up and calls the game's own
        send_directed_chat function.

        Args:
            message: The chat message text (max 7 characters for now)
            target_gid: The target player's GID

        Raises:
            ValueError: If message exceeds 7 characters
            RuntimeError: If ChatSendHook is not active
        """
        if len(message) > _MAX_SSO_WCHARS:
            raise ValueError(
                f"Message too long ({len(message)} chars, max {_MAX_SSO_WCHARS}). "
                f"Longer messages require heap-allocated wstrings (not yet implemented)."
            )

        trigger_addr = self.hook_handler._base_addrs.get("send_trigger")
        struct_addr = self.hook_handler._base_addrs.get("send_struct")
        if trigger_addr is None or struct_addr is None:
            raise RuntimeError(
                "ChatSendHook not active. Call "
                "hook_handler.activate_chat_send_hook() first."
            )

        # Build the DirectedChatRequest struct
        wchars = message.encode("utf-16-le")
        struct_data = bytearray(_STRUCT_SIZE)
        struct_data[0x00:0x00 + len(wchars)] = wchars   # inline SSO
        struct.pack_into("<Q", struct_data, 0x10, len(message))  # size
        struct.pack_into("<Q", struct_data, 0x18, 7)             # capacity (SSO)
        struct.pack_into("<Q", struct_data, 0x20, target_gid)    # target GID

        # Write struct to the hook's export buffer
        await self.hook_handler.write_bytes(struct_addr, bytes(struct_data))

        # Set trigger — the main thread hook picks this up next frame
        await self.hook_handler.write_bytes(trigger_addr, b"\x01")

        # Wait for the hook to clear the trigger (send complete)
        for _ in range(100):  # ~5 seconds at 20 FPS
            await asyncio.sleep(0.05)
            result = await self.hook_handler.read_bytes(trigger_addr, 1)
            if result == b"\x00":
                return

        raise RuntimeError("Chat send timed out — trigger was not cleared by hook")


class DynamicChatOwner(DynamicMemoryObject, ChatOwner):
    pass


class CurrentChatOwner(ChatOwner):
    """Reads the chat owner address from the ChatHook export.

    Note: send_msg() does not require ChatHook — it uses
    ChatSendHook + the GameClient from ClientHook instead.
    The ChatHook is only needed for reading incoming message data.
    """

    async def read_base_address(self) -> int:
        return await self.hook_handler.read_chat_owner_base()
