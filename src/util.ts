import { constants as fsConstants } from "node:fs";
import { lstat, open, readFile, readdir, stat } from "node:fs/promises";
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

/** Read a sandbox-written JSON artifact without following symlinks. */
export async function readJsonArtifact<T>(outputDir: string, filename: string): Promise<T> {
  if (path.basename(filename) !== filename || filename === "." || filename === "..") {
    throw new Error("artifact name must be a direct child filename");
  }
  const rootInfo = await lstat(outputDir);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new Error("artifact output directory must be a regular directory");
  }
  const dirHandle = await open(outputDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  try {
    const openedRoot = await dirHandle.stat();
    if (!openedRoot.isDirectory() || openedRoot.dev !== rootInfo.dev || openedRoot.ino !== rootInfo.ino) {
      throw new Error("artifact output directory changed while opening");
    }
    // Resolve the child relative to the pinned directory fd for both lstat and
    // open. No pathname outside this directory is considered or followed.
    const artifactPath = `/proc/self/fd/${dirHandle.fd}/${filename}`;
    const before = await lstat(artifactPath);
    if (!before.isFile() || before.isSymbolicLink()) throw new Error("artifact must be a regular non-symlink file");

    // O_NOFOLLOW rejects a final-component symlink even if the name changes
    // after lstat. O_NONBLOCK avoids hanging if it is raced with a FIFO.
    const artifactHandle = await open(
      artifactPath,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
    );
    try {
      const openedArtifact = await artifactHandle.stat();
      if (!openedArtifact.isFile() || openedArtifact.dev !== before.dev || openedArtifact.ino !== before.ino) {
        throw new Error("artifact changed while opening");
      }
      return JSON.parse(await artifactHandle.readFile("utf8")) as T;
    } finally {
      await artifactHandle.close();
    }
  } finally {
    await dirHandle.close();
  }
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
