#!/usr/bin/env -S deno test -A --unstable
import { $ } from "https://deno.land/x/dax/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

await $`cargo build --release`;

Deno.test("linking", async () => {
  const output = await $`otool -L target/release/deno_native_certs_test`.stdout(
    "piped",
  );
  const dylibs = output.stdout.split("\n").slice(1).map((line) =>
    line.split(" ")[0].trim()
  ).filter((line) => line.length > 0);
  const expected = [
    "/usr/lib/libiconv.2.dylib",
    "/usr/lib/libSystem.B.dylib",
  ];
  assertEquals(dylibs.sort(), expected.sort());
});
