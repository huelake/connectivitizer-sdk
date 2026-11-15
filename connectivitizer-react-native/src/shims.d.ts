// The two functions this package uses from the app's Expo packages, declared here so that the package
// builds without installing Expo and React Native. In the app the real type definitions apply.

declare module 'expo' {
  export function requireOptionalNativeModule<T>(name: string): T | null;
}

declare module 'expo-crypto' {
  export function getRandomBytes(byteCount: number): Uint8Array;
}

declare function atob(data: string): string;
declare const console: { warn(...data: unknown[]): void };
