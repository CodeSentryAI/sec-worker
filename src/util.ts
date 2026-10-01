import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

export async function exists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

export async function isExecutable(p: string): Promise<boolean> {
  try {
    const s = await stat(p);
    return s.isFile() && (s.mode & 0o111) !== 0;
  } catch { return false; }
}

export async function listFilesRecursive(root: string, maxDepth = 6): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > maxDepth) return;
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) await walk(full, depth + 1);
      else if (e.isFile()) out.push(full);
    }
  }
  await walk(root, 0);
  return out;
}

export async function readJson<T>(p: string): Promise<T> {
  return JSON.parse(await readFile(p, "utf8")) as T;
}

/** Copy a directory tree with regular files only (symlinks dereferenced). */
export async function copyDir(src: string, dest: string): Promise<void> {
  const s = await stat(src);
  if (!s.isDirectory()) throw new Error(`not a directory: ${src}`);
  await copyInner(src, dest, 0);
}

async function copyInner(src: string, dest: string, depth: number): Promise<void> {
  if (depth > 12) return;
  const { mkdir, readdir, copyFile } = await import("node:fs/promises");
  await mkdir(dest, { recursive: true });
  const entries = await readdir(src, { withFileTypes: true });
  for (const e of entries) {
    const from = path.join(src, e.name);
    const to = path.join(dest, e.name);
    if (e.isDirectory()) await copyInner(from, to, depth + 1);
    else if (e.isFile()) await copyFile(from, to);
  }
}
