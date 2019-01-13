#ifndef WH_SERDES_H
#define WH_SERDES_H

#include <lua.h>

/** Reads `fd`, deserializes one element and pushes it in the stack.
 *
 * Returns 1 if an element was read; 0 if none element was read; -1 if
 * deserialization failed.
 */
int luaW_read(lua_State* L, int fd);

/** Reads `fd`, deserializes all elements and pushes them in the stack.
 *
 * Returns 0 if succeed, else -1.
 */
int luaW_readstack(lua_State* L, int fd);

/** Serializes element at index `idx` and writes it in `fd`.
 *
 * Returns 1 if an element was written; 0 if not element was written; raises a
 * Lua error if something went wrong.
 */
int luaW_write(lua_State* L, int idx, int fd);

/** Serializes the stack from index `idx` and writes them in `fd`.
 *
 * Raises a Lua error if something went wrong.
 */
void luaW_writestack(lua_State* L, int idx, int fd);

/** Serializes element LUA_TNONE and writes it in `fd`.
 *
 * Returns 1 if written; 0 if not.
 */
void luaW_writenone(int fd);

#endif  // WH_SERDES_H

