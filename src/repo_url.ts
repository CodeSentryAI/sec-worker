/**
 * Canonical GitHub repository URL parsing for the repo-url entry point.
 *
 * Accepted input is exactly `https://github.com/OWNER/REPO` with an optional
 * `.git` suffix. Everything else is rejected up front so that no user string
 * ever reaches git as more than an opaque identifier, and so the only host the
 * worker will ever talk to for acquisition is github.com.
 */

export interface RepoRef {
  host: "github.com";
  owner: string;
  repo: string;
  /** Owner/repo without the `.git` suffix, as GitHub displays it. */
  slug: string;
  /** Exactly what was accepted, normalized only by dropping a `.git` suffix. */
  canonicalUrl: string;
  /** What git is asked to clone: the canonical URL plus `.git`. */
  cloneUrl: string;
}

export class RepoUrlError extends Error {
  readonly reason: RepoUrlErrorReason;
  constructor(reason: RepoUrlErrorReason, message: string) {
    super(message);
    this.name = "RepoUrlError";
    this.reason = reason;
  }
}

export type RepoUrlErrorReason =
  | "empty"
  | "credentials"
  | "scheme"
  | "host"
  | "port"
  | "query-or-fragment"
  | "path"
  | "illegal-characters";

const ALLOWED_HOST = "github.com";

/** GitHub account names: alphanumerics with isolated interior hyphens, max 39. */
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
/** GitHub repo names: alphanumerics, dot, hyphen, underscore. */
const REPO_RE = /^[A-Za-z0-9_.-]{1,100}$/;

function fail(reason: RepoUrlErrorReason, message: string): never {
  throw new RepoUrlError(reason, message);
}

/** True when the string contains a C0 control character or DEL. */
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * Parse a public GitHub repository URL.
 *
 * Rejects, in order: empty input, characters that must never appear in a URL we
 * accept (whitespace, control chars, backslash), anything that is not the
 * `https` scheme, embedded credentials, a non-github.com host, an explicit
 * port, a query or fragment, and any path that is not exactly OWNER/REPO.
 */
export function parseRepoUrl(input: unknown): RepoRef {
  if (typeof input !== "string" || input.trim() === "") fail("empty", "repository URL is empty");
  const raw: string = input;

  if (/[\s\\]/.test(raw) || hasControlChar(raw)) {
    fail("illegal-characters", "repository URL contains whitespace, a backslash, or a control character");
  }
  if (raw.includes("@")) {
    fail("credentials", "repository URL must not contain credentials or an SSH user");
  }

  const schemeSep = raw.indexOf("://");
  if (schemeSep < 0) fail("scheme", "repository URL must start with https://");
  const scheme = raw.slice(0, schemeSep);
  if (scheme !== "https") {
    fail("scheme", `only canonical https:// URLs are accepted, got '${scheme}://'`);
  }

  const afterScheme = raw.slice(schemeSep + 3);
  if (afterScheme.includes("//")) fail("path", "repository URL has an empty or repeated path separator");

  const queryAt = afterScheme.search(/[?#]/);
  if (queryAt >= 0) {
    const tail = afterScheme.slice(queryAt);
    fail(
      "query-or-fragment",
      tail.startsWith("?")
        ? "repository URL must not carry a query string"
        : "repository URL must not carry a fragment",
    );
  }

  const segments = afterScheme.split("/");
  if (segments.length < 1 || segments[0] === "") fail("host", "repository URL has no host");
  const host = segments[0]!;

  const portAt = host.indexOf(":");
  if (portAt >= 0) fail("port", `repository URL must not specify a port (got '${host.slice(portAt)}')`);
  if (host !== ALLOWED_HOST) {
    fail("host", `only ${ALLOWED_HOST} is accepted, got '${host}'`);
  }

  const pathSegments = segments.slice(1);
  if (pathSegments.length === 0 || pathSegments[0] === "" || pathSegments.length > 2) {
    fail("path", "repository path must be exactly OWNER/REPO");
  }
  if (pathSegments.length === 1) fail("path", "repository path must name both OWNER and REPO");

  const owner = pathSegments[0]!;
  let repo = pathSegments[1]!;
  if (repo.endsWith(".git")) repo = repo.slice(0, -".git".length);
  if (repo === "") fail("path", "repository name is empty");

  if (owner === "." || owner === ".." || repo === "." || repo === "..") {
    fail("path", "repository path must not contain relative segments");
  }
  if (!OWNER_RE.test(owner)) fail("path", `owner '${owner}' is not a valid GitHub account name`);
  if (!REPO_RE.test(repo)) fail("path", `'${repo}' is not a valid GitHub repository name`);

  const canonicalUrl = `https://${ALLOWED_HOST}/${owner}/${repo}`;
  return {
    host: ALLOWED_HOST,
    owner,
    repo,
    slug: `${owner}/${repo}`,
    canonicalUrl,
    cloneUrl: `${canonicalUrl}.git`,
  };
}
