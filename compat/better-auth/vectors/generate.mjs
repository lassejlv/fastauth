// Writes better-auth.json: signed cookies and password hashes made by Better Auth's code,
// which fastauth's tests verify (crates/fastauth-core/tests/better_auth_compat.rs).
//
//   npm ci && node generate.mjs
import { createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
import { getSignedCookie, hashPassword, signedCookie, verifyPassword, versions } from "./common.mjs";

const cookieSecrets = [
  // openssl rand -base64 32: what most apps use.
  "Zp1n3pXcQ3gyq0z0r1f8m2Kq4bVw9tYvJ6cL5dHs7uE=",
  // 64 hex characters, which fastauth's Secret::from_base64 would decode; Better Auth uses
  // the characters as they are.
  "6f1c0d5e9a2b4c7d8e3f6a1b2c5d4e7f9a0b3c6d8e1f2a5b4c7d0e9f8a3b6c1d",
  // Non-ASCII: the key is the UTF-8 bytes.
  "sécret-ünïcödé-🔑-0123456789-abcdefghijklmnop",
];

const tokens = [
  "Xq3mR8vT1kL9pZ2nB6cF4hJ7wY0sA5dE", // Better Auth's generateId(32)
  "kq3_mR8vT1kL-pZ2nB6cF4hJ7wY0sA5dEu9iO8yT6rW", // fastauth's random_token()
  "true", // the dont_remember marker
  "a b",
  "tok:1",
  "a;b,c=d",
  "100%",
  "+/=?&#",
  "ünïcödé",
  "🔑",
  "\"quoted\"",
  "!~*'()-_.",
  "x".repeat(300),
];

const hmac = (secret, value) => createHmac("sha256", Buffer.from(secret, "utf8")).update(value).digest("base64");

const cookies = [];
for (const secret of cookieSecrets) {
  const name = "vt.session_token";
  const signed = [];
  for (const value of tokens) {
    const cookie = await signedCookie(name, value, secret);
    const back = await getSignedCookie(`${name}=${cookie}`, name, secret);
    if (back !== value) throw new Error(`better-call doesn't read back ${JSON.stringify(value)}`);
    signed.push({ value, cookie });
  }

  const token = tokens[0];
  const good = signed[0].cookie;
  const sig = hmac(secret, token);
  const tampered = `${token.slice(0, -1)}Q.${encodeURIComponent(sig)}`;
  const raw = [
    ["encoded, as set", `${name}=${good}`],
    ["not encoded", `${name}=${token}.${sig}`],
    ["quoted", `${name}="${good}"`],
    ["among other cookies", `a=1; ${name}=${good}; b=2`],
    ["spaces around the value", `${name}=  ${good}  `],
    ["first of two wins (good first)", `${name}=${good}; ${name}=junk`],
    ["first of two wins (bad first)", `${name}=${tampered}; ${name}=${good}`],
    ["another name", `x${name}=${good}`],
    ["tampered value", `${name}=${tampered}`],
    ["signed with another secret", `${name}=${token}.${encodeURIComponent(hmac(secret + "x", token))}`],
    ["signature without padding", `${name}=${token}.${sig.replace(/=+$/, "")}`],
    ["url-safe signature", `${name}=${token}.${sig.replace(/\+/g, "-").replace(/\//g, "_")}`],
    ["empty value", `${name}=.${encodeURIComponent(hmac(secret, ""))}`],
    ["no signature", `${name}=${token}`],
    ["empty cookie", `${name}=`],
    ["malformed escape, signed raw", `${name}=abc%zz.${hmac(secret, "abc%zz")}`],
    ["malformed escape, signed decoded", `${name}=abc%zz.${hmac(secret, "abc%")}`],
    ["invalid UTF-8 escape", `${name}=a%FFb.${hmac(secret, "a%FFb")}`],
    ["encoded dot in the value", `${name}=${encodeURIComponent(`a.b.${hmac(secret, "a.b")}`)}`],
    ["percent-encoded twice", `${name}=${encodeURIComponent(good)}`],
    ["lowercase escapes", `${name}=${good.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase())}`],
  ];
  const parse = [];
  for (const [label, header] of raw) {
    parse.push({ label, header, result: await getSignedCookie(header, name, secret) });
  }
  cookies.push({ secret, name, signed, parse });
}

const passwords = [
  ["plain", "correct horse battery staple", ["correct horse battery staple "]],
  ["ligature fi", "\uFB01nance", ["finance"]],
  ["fi alone", "\uFB01", ["fi"]],
  ["combining acute", "cafe\u0301", ["café"]],
  ["precomposed acute", "café", ["cafe\u0301"]],
  ["full-width", "\uFF50\uFF41\uFF53\uFF53\uFF57\uFF4F\uFF52\uFF44", ["password"]],
  ["half-width katakana", "\uFF8A\uFF9F\uFF7D\uFF9C\uFF70\uFF84\uFF9E", ["パスワード"]],
  ["circled digits", "\u2460\u2461\u2462\u2463", ["1234"]],
  ["angstrom sign", "\u212B", ["\u00C5"]],
  ["superscript", "x\u00B2", ["x2"]],
  ["sharp s", "straße", ["strasse"]],
  ["arabic ligature", "\uFDFA", []],
  ["emoji", "🔑🔒 secret", []],
  ["empty", "", [" "]],
  ["one space", " ", [""]],
  ["whitespace", "\t\n ", []],
  ["nul byte", "a\u0000b", ["ab"]],
  ["128 characters", "p".repeat(128), ["p".repeat(127)]],
  ["1000 characters", "Lorem ipsum ".repeat(84).slice(0, 1000), []],
];

const scrypt = [];
for (const [label, password, others] of passwords) {
  const hash = await hashPassword(password);
  const checks = [{ password, result: await verifyPassword(hash, password) }];
  for (const other of others) checks.push({ password: other, result: await verifyPassword(hash, other) });
  checks.push({ password: password + "x", result: await verifyPassword(hash, password + "x") });
  if (!checks[0].result) throw new Error(`Better Auth doesn't verify its own hash of ${label}`);
  scrypt.push({ label, password, hash, checks });
}

// Hash strings Better Auth accepts or refuses, verified against "pw".
const known = await hashPassword("pw");
const [salt, key] = known.split(":");
const odd = [
  ["extra part ignored", `${salt}:${key}:extra`],
  ["uppercase key", `${salt}:${key.toUpperCase()}`],
  ["no colon", `${salt}${key}`],
  ["empty salt", `:${key}`],
  ["empty key", `${salt}:`],
];
const malformed = [];
for (const [label, hash] of odd) {
  let result;
  try {
    result = await verifyPassword(hash, "pw");
  } catch {
    result = "error";
  }
  malformed.push({ label, hash, password: "pw", result });
}

writeFileSync(
  new URL("./better-auth.json", import.meta.url),
  `${JSON.stringify({ generator: { ...versions, node: process.version }, cookies, scrypt, malformed }, null, 2)}\n`,
);
console.log(`wrote better-auth.json: ${cookies.length} secrets, ${scrypt.length} passwords`);
