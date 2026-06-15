import { describe, it, expect } from "vitest";
import {
  redact,
  REDACTED,
  approximateEntropyBits,
  valueLooksSecret,
  canonicalJSONStringify,
} from "../../src/audit/redact.js";

describe("redact: by key name", () => {
  it("redacts values whose key looks like a secret", () => {
    const r = redact({
      username: "alice",
      password: "hunter2",
      apiKey: "AKIAIOSFODNN7EXAMPLE",
      api_key: "another-one",
      token: "abc",
      authorization: "Bearer xyz",
      sessionId: "deadbeef",
      cookie: "sid=foo",
      privateKey: "----- pem -----",
    });
    expect(r).toMatchObject({
      username: "alice",
      password: REDACTED,
      apiKey: REDACTED,
      api_key: REDACTED,
      token: REDACTED,
      authorization: REDACTED,
      sessionId: REDACTED,
      cookie: REDACTED,
      privateKey: REDACTED,
    });
  });

  it("propagates the secret context into nested objects", () => {
    const r = redact({
      credentials: {
        primary: { value: "should-be-redacted" },
        backup: ["also-redacted", "and-this"],
      },
    }) as any;
    expect(r.credentials.primary.value).toBe(REDACTED);
    expect(r.credentials.backup).toEqual([REDACTED, REDACTED]);
  });

  it("matches case-insensitively", () => {
    const r = redact({ APIKey: "foo", Password: "bar", SECRET_TOKEN: "baz" }) as any;
    expect(r.APIKey).toBe(REDACTED);
    expect(r.Password).toBe(REDACTED);
    expect(r.SECRET_TOKEN).toBe(REDACTED);
  });
});

describe("redact: by value shape", () => {
  it("redacts known credential prefixes regardless of key name", () => {
    const r = redact({
      note: "sk-abcdef0123456789ABCDEF",
      ghToken: "github_pat_11ABCDE0CrmevyHFSbojABCDEFGHIJKLMNOPQRSTUVWXYZ",
      anthropic: "sk-ant-abcdef0123456789ABCDEFG",
      classic: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
      aws: "AKIAIOSFODNN7EXAMPLE",
      slack: "xoxb-12345-abcdef-XYZ",
      jwt: "eyJabcdefghijklmnopqrstuv.eyJabc.def",
    }) as any;
    expect(r.note).toBe(REDACTED);
    expect(r.ghToken).toBe(REDACTED);
    expect(r.anthropic).toBe(REDACTED);
    expect(r.classic).toBe(REDACTED);
    expect(r.aws).toBe(REDACTED);
    expect(r.slack).toBe(REDACTED);
    expect(r.jwt).toBe(REDACTED);
  });

  it("redacts long high-entropy opaque blobs", () => {
    const opaque = "kJ8DfM4lQ2pXq7tWvR9zE3yA1cBhN6sUiOaPbZ5gHj"; // 41 chars, mixed
    expect(valueLooksSecret(opaque)).toBe(true);
    const r = redact({ blob: opaque }) as any;
    expect(r.blob).toBe(REDACTED);
  });

  it("leaves normal English prose alone", () => {
    const note = "Please summarize the quarterly results document.";
    const r = redact({ note }) as any;
    expect(r.note).toBe(note);
  });

  it("leaves short or low-entropy strings alone", () => {
    const r = redact({ name: "alice", role: "admin", code: "ABC123" }) as any;
    expect(r.name).toBe("alice");
    expect(r.role).toBe("admin");
    expect(r.code).toBe("ABC123");
  });

  it("survives null, undefined, numbers, booleans, arrays", () => {
    expect(redact(null)).toBe(null);
    expect(redact(undefined)).toBe(undefined);
    expect(redact(42)).toBe(42);
    expect(redact(true)).toBe(true);
    expect(redact(["alice", "bob"])).toEqual(["alice", "bob"]);
  });

  it("handles cyclic objects without stack overflow", () => {
    const a: any = { name: "a" };
    a.self = a;
    expect(() => redact(a)).not.toThrow();
  });
});

describe("approximateEntropyBits", () => {
  it("scores random alphanumerics high", () => {
    expect(approximateEntropyBits("kJ8DfM4lQ2pXq7tWvR9zE3yA1cBh")).toBeGreaterThan(4.0);
  });
  it("scores repeated chars low", () => {
    expect(approximateEntropyBits("aaaaaaaaaaaaaaaa")).toBe(0);
  });
});

describe("canonicalJSONStringify", () => {
  it("produces sorted-key output regardless of insertion order", () => {
    const a = JSON.parse('{"b":2,"a":1,"c":{"y":2,"x":1}}');
    const b = JSON.parse('{"c":{"x":1,"y":2},"a":1,"b":2}');
    expect(canonicalJSONStringify(a)).toBe(canonicalJSONStringify(b));
  });
});
