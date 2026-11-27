// Checks values fastauth made (fastauth.json, or the file given) with Better Auth's code:
// better-call must read every signed cookie back, sign each value to the same bytes, and
// @better-auth/utils must verify every password hash.
//
//   node check.mjs [path/to/fastauth.json]
import { readFileSync } from "node:fs";
import { getSignedCookie, signedCookie, verifyPassword } from "./common.mjs";

const path = process.argv[2] ?? new URL("./fastauth.json", import.meta.url);
const vectors = JSON.parse(readFileSync(path, "utf8"));
const failures = [];
let checked = 0;

for (const { secret, name, signed } of vectors.cookies) {
  for (const { value, cookie } of signed) {
    checked++;
    const read = await getSignedCookie(`${name}=${cookie}`, name, secret);
    if (read !== value) failures.push(`cookie ${JSON.stringify(cookie)}: better-call read ${JSON.stringify(read)}`);
    const ours = await signedCookie(name, value, secret);
    if (ours !== cookie) failures.push(`cookie for ${JSON.stringify(value)}: better-call signs ${ours}, fastauth ${cookie}`);
  }
}

for (const { password, hash } of vectors.scrypt) {
  checked++;
  if (!(await verifyPassword(hash, password))) failures.push(`hash of ${JSON.stringify(password)} doesn't verify`);
  if (await verifyPassword(hash, password + "x")) failures.push(`hash of ${JSON.stringify(password)} verifies a wrong password`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  console.error(`${failures.length} of ${checked} fastauth values fail in Better Auth`);
  process.exit(1);
}
console.log(`Better Auth accepts all ${checked} fastauth values in ${path}`);
