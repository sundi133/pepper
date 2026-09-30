// Minimal typing for js-yaml (present via the eslint toolchain); used only by
// tests to parse generated CI templates.
declare module "js-yaml" {
  export function load(input: string): unknown;
}
