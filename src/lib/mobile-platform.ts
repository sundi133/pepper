/**
 * Which mobile platform an uploaded app file is for. Kept free of server-only
 * imports: the upload form, the API and the worker all use it.
 */

export type MobilePlatform = "android" | "ios";

const PLATFORM_EXTENSIONS: Record<string, MobilePlatform> = {
  ".apk": "android",
  ".aab": "android",
  ".ipa": "ios",
};

/** Android or iOS for an .apk / .aab / .ipa file name, else null. */
export function mobilePlatformOf(fileName: string | null | undefined): MobilePlatform | null {
  const m = fileName?.toLowerCase().match(/\.[a-z0-9]+$/);
  return (m && PLATFORM_EXTENSIONS[m[0]]) || null;
}

export const MOBILE_PLATFORM_LABELS: Record<MobilePlatform, string> = {
  android: "Android",
  ios: "iOS",
};
