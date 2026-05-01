import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

const CACHE_DIR = join(homedir(), ".cache", "pi-kevin");

export async function ensureCacheDir(): Promise<string> {
  await mkdir(CACHE_DIR, { recursive: true });
  return CACHE_DIR;
}

export function isFresh(timestamp: number | undefined, ttlMs: number): boolean {
  return typeof timestamp === "number" && Date.now() - timestamp < ttlMs;
}

export async function readJsonCache<T>(name: string): Promise<T | undefined> {
  try {
    const dir = await ensureCacheDir();
    const path = join(dir, name);
    const raw = await readFile(path, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return undefined;
  }
}

export async function writeJsonCache(name: string, value: unknown): Promise<void> {
  const dir = await ensureCacheDir();
  const path = join(dir, name);
  await writeFile(path, JSON.stringify(value, null, 2), "utf8");
}
