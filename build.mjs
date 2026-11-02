#!/usr/bin/env node
/**
 * Build the publishable artifacts.
 *
 *   node build.mjs                        # name = dsh-auth-cookie-guard
 *   node build.mjs --owner someuser       # also writes repository/homepage/bugs
 *   node build.mjs --name @scope/pkg      # rename the published package
 *   node build.mjs --git                  # init/commit the release tree as a repo
 *
 * Output (all under ./release):
 *
 *   <name>/                        clean, git-ready tree (what goes to GitHub)
 *   <name>-<version>.tgz           npm tarball — what users install
 *   <name>-<version>-source.zip    the same tree zipped for upload
 *   SHA256SUMS.txt                 checksums of the two archives
 *
 * The working directory keeps the `@local/…` name so the same files can be linked
 * into a local Harness profile (`pnpm link`) without colliding with the published
 * package name; this script rewrites the name (and the loader row that refers to
 * it) in the release copy.
 */

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(fileURLToPath(import.meta.url))

/** Files that make up the public tree; everything else stays local. */
const TREE = [
  'index.js',
  'cordis.patch.yml',
  'icon.svg',
  'README.md',
  'LICENSE',
  'CHANGELOG.md',
  '.gitignore',
  'build.mjs',
  'test/guard.test.mjs',
  '.github/workflows/ci.yml',
  'locale',
]

function parseArgs(argv) {
  const options = { name: 'dsh-auth-cookie-guard', owner: undefined, git: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--name') options.name = argv[++i]
    else if (arg === '--owner') options.owner = argv[++i]
    else if (arg === '--git') options.git = true
    else throw new Error(`unknown argument: ${arg}`)
  }
  if (typeof options.name !== 'string' || options.name.length === 0) throw new Error('--name needs a value')
  return options
}

function copyTree(from, to) {
  const info = statSync(from)
  if (info.isDirectory()) {
    mkdirSync(to, { recursive: true })
    for (const entry of readdirSync(from)) copyTree(join(from, entry), join(to, entry))
    return
  }
  mkdirSync(dirname(to), { recursive: true })
  copyFileSync(from, to)
}

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

const options = parseArgs(process.argv.slice(2))
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const outDir = join(root, 'release')
const treeDir = join(outDir, options.name)

// A rebuild replaces the whole release directory; keep a repository that already
// lives inside the release tree (so `--git` users can rebuild without losing history).
const releaseGit = join(treeDir, '.git')
const stash = existsSync(releaseGit) ? join(tmpdir(), `dsh-guard-git-${process.pid}-${Date.now()}`) : undefined
if (stash !== undefined) renameSync(releaseGit, stash)

rmSync(outDir, { recursive: true, force: true })
mkdirSync(outDir, { recursive: true })

for (const entry of TREE) copyTree(join(root, entry), join(treeDir, entry))

// package.json: publishable identity, no workspace-only fields.
const published = { ...pkg, name: options.name }
delete published.private
if (options.owner !== undefined) {
  const slug = `${options.owner}/${basename(options.name)}`
  published.repository = { type: 'git', url: `git+https://github.com/${slug}.git` }
  published.homepage = `https://github.com/${slug}#readme`
  published.bugs = { url: `https://github.com/${slug}/issues` }
}
writeFileSync(join(treeDir, 'package.json'), `${JSON.stringify(published, null, 2)}\n`, 'utf8')

// cordis.patch.yml refers to the package by name; follow the rename.
const patchPath = join(treeDir, 'cordis.patch.yml')
const patch = readFileSync(patchPath, 'utf8')
writeFileSync(patchPath, patch.split(pkg.name).join(options.name), 'utf8')

// npm tarball: stage exactly what `files` ships, under the `package/` prefix npm
// itself uses, then tar it. Doing this without npm keeps the build offline-safe
// and avoids Windows `npm.cmd` spawn quirks.
const PACKED = [
  'package.json',
  'index.js',
  'cordis.patch.yml',
  'icon.svg',
  'README.md',
  'LICENSE',
  'CHANGELOG.md',
  'locale',
]
const stageDir = join(outDir, '.pack')
for (const entry of PACKED) copyTree(join(treeDir, entry), join(stageDir, 'package', entry))
const tarball = join(outDir, `${basename(options.name)}-${published.version}.tgz`)
execFileSync('tar', ['-czf', tarball, '-C', stageDir, 'package'], { stdio: 'inherit' })
rmSync(stageDir, { recursive: true, force: true })

// source zip (tar handles the .zip suffix on Windows 10+ and everywhere else)
const zip = join(outDir, `${basename(options.name)}-${published.version}-source.zip`)
execFileSync('tar', ['-a', '-c', '-f', zip, '-C', outDir, options.name], { stdio: 'inherit' })

// Repository: restore the preserved .git, or start one for `--git`. Done after the
// archives so `.git` never ends up inside the tarball or the source zip.
if (stash !== undefined) {
  renameSync(stash, join(treeDir, '.git'))
} else if (options.git) {
  execFileSync('git', ['init', '-b', 'main'], { cwd: treeDir, stdio: 'inherit' })
}
if (options.git) {
  execFileSync('git', ['add', '-A'], { cwd: treeDir, stdio: 'inherit' })
  execFileSync('git', ['commit', '-m', `release v${published.version}`, '--allow-empty'], {
    cwd: treeDir,
    stdio: 'inherit',
  })
}
const hasGit = existsSync(join(treeDir, '.git'))

writeFileSync(
  join(outDir, 'SHA256SUMS.txt'),
  `${sha256(tarball)}  ${basename(tarball)}\n${sha256(zip)}  ${basename(zip)}\n`,
  'utf8',
)

const kb = (file) => `${(statSync(file).size / 1024).toFixed(1)} KB`
console.log(`
release tree   ${treeDir}${hasGit ? '  (git repo)' : ''}
npm tarball    ${basename(tarball)}  (${kb(tarball)})
source zip     ${basename(zip)}  (${kb(zip)})
checksums      SHA256SUMS.txt
`)
