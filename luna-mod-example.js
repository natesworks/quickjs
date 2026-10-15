/*
 * Example Luna mod.
 *
 * Compile with:
 *   tools/luna/lunac.py build ./mods/com.luna.mods.example --antimod antimod.json
 *
 * A mod is an ES module: everything it exports is its public api, and other
 * mods import it by package name.
 */
import { log } from 'com.luna.mods.core';

export const NAME = 'example';
export const VERSION = '1.0.0';

export function greet(who) {
  log(`example: greeting ${who}`);
  return `hello ${who} from ${NAME} ${VERSION}`;
}

export default { NAME, VERSION, greet };
