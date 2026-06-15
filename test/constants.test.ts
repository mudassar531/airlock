import { describe, it, expect } from "vitest";
import { PRODUCT_NAME, getPackageVersion } from "../src/constants.js";

describe("constants", () => {
  it("PRODUCT_NAME is the canonical product name", () => {
    expect(PRODUCT_NAME).toBe("airlock");
  });

  it("getPackageVersion returns a semver-like string", () => {
    const version = getPackageVersion();
    expect(version).toMatch(/^\d+\.\d+\.\d+(?:[-+].+)?$/);
  });
});
