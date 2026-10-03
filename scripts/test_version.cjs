const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');

const source = path.resolve(__dirname, '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'p2ptap-version-'));
const repo = path.join(temp, 'repo');
const bash = process.env.BASH_EXE || (process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash');
const pwsh = process.env.PWSH_EXE || 'pwsh';
const cleanEnv = { ...process.env, P2PTAP_VERSION: '', P2PTAP_SOURCE_VERSION: '', TZ: 'Pacific/Honolulu' };
function git(...args) {
  return cp.execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
}
function installHelpers(dir) {
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true });
  for (const name of ['get_version.sh', 'get_version.ps1', 'check_release_tag.sh']) {
    fs.copyFileSync(path.join(source, 'scripts', name), path.join(dir, 'scripts', name));
  }
}
function resolveVersion(dir, version = '', ref = 'HEAD', extraEnv = {}) {
  return [
    cp.spawnSync(bash, [path.join(dir, 'scripts/get_version.sh').replaceAll('\\', '/'), version, ref], { encoding: 'utf8', env: { ...cleanEnv, ...extraEnv } }),
    cp.spawnSync(pwsh, ['-NoProfile', '-File', path.join(dir, 'scripts/get_version.ps1'), '-Version', version, '-SourceRef', ref], { encoding: 'utf8', env: { ...cleanEnv, ...extraEnv } }),
  ];
}
function checkVersions(version, expected, ref = 'HEAD', env = {}) {
  for (const result of resolveVersion(repo, version, ref, env)) {
    assert.equal(result.status, 0, result.stderr || String(result.error));
    assert.equal(result.stdout.trim(), expected);
  }
}
// Execute the actual prepare-step shell scripts with synthetic workflow inputs.
// No build, tag creation, feed push or Release API is invoked by these steps.
function prepare(file, env) {
  const workflow = fs.readFileSync(path.join(source, '.github/workflows', file), 'utf8').split(/\r?\n/);
  const id = workflow.findIndex(line => /^\s+(?:- )?id: version$/.test(line));
  const run = workflow.findIndex((line, index) => index > id && /^\s+run: \|$/.test(line));
  assert.ok(id >= 0 && run > id);
  const indent = workflow[run].match(/^ */)[0].length + 2;
  const lines = [];
  for (let i = run + 1; i < workflow.length; i++) {
    if (workflow[i].trim() && workflow[i].match(/^ */)[0].length < indent) break;
    lines.push(workflow[i].slice(indent));
  }
  const output = path.join(temp, 'outputs');
  fs.writeFileSync(output, '');
  const result = cp.spawnSync(bash, ['-c', lines.join('\n')], {
    cwd: repo, encoding: 'utf8', env: { ...cleanEnv, GITHUB_SHA: git('rev-parse', 'HEAD'), GITHUB_REF: 'refs/heads/main', GITHUB_REF_NAME: 'main', GITHUB_OUTPUT: output.replaceAll('\\', '/'), INPUT_VERSION: '', PUBLISH_RELEASE: 'false', PUBLISH_FEED: '', ...env },
  });
  return { ...result, outputs: Object.fromEntries(fs.readFileSync(output, 'utf8').trim().split('\n').filter(Boolean).map(line => line.split('='))) };
}

try {
  fs.mkdirSync(repo);
  git('init', '-q');
  git('config', 'user.name', 'Version Contract Test');
  git('config', 'user.email', 'version-test@example.invalid');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'tag.gpgsign', 'false');
  git('commit', '--allow-empty', '-qm', 'first');
  const first = git('rev-parse', 'HEAD');
  git('tag', 'v9.9.9');
  git('commit', '--allow-empty', '-qm', 'second');
  const second = git('rev-parse', 'HEAD');
  git('tag', '-a', 'v9.9.8', '-m', 'same commit annotated tag');
  installHelpers(repo);
  const date = new Date().toISOString().slice(0, 10).replaceAll('-', '');
  const auto = `v1.0.${date}.2-${second.slice(0, 7)}`;
  checkVersions('', auto);
  const culture = cp.spawnSync(pwsh, ['-NoProfile', '-Command', "[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('th-TH'); & $env:VERSION_TEST_HELPER"], { encoding: 'utf8', env: { ...cleanEnv, VERSION_TEST_HELPER: path.join(repo, 'scripts/get_version.ps1') } });
  assert.equal(culture.status, 0, culture.stderr);
  assert.equal(culture.stdout.trim(), auto);
  checkVersions('', `v1.0.${date}.1-${first.slice(0, 7)}`, first);
  checkVersions('1.2.3', 'v1.2.3');
  checkVersions('v1.0.20261003.60-abc1234', 'v1.0.20261003.60-abc1234');
  checkVersions('', 'v2.3.4', 'HEAD', { P2PTAP_VERSION: 'v2.3.4' });
  checkVersions('v4.5.6', 'v4.5.6', 'HEAD', { P2PTAP_VERSION: 'v2.3.4' });
  for (const result of resolveVersion(repo, '', 'missing-source-ref')) assert.notEqual(result.status, 0);
  for (const invalid of ['v1.2.3-rc1', 'v1.2.3;echo bad', 'v1.2.3\n', 'v1.2.3\n4', ' main ', 'v1.0.20261003.60-abc12345']) {
    // Git Bash's Windows argv adapter trims trailing newlines; environment input
    // preserves them and exercises the same untrusted input as workflow_dispatch.
    for (const result of resolveVersion(repo, '', 'HEAD', { P2PTAP_VERSION: invalid })) assert.notEqual(result.status, 0, invalid);
  }
  const shallow = path.join(temp, 'shallow');
  cp.execFileSync('git', ['clone', '-q', '--depth=1', pathToFileURL(repo).href, shallow]);
  installHelpers(shallow);
  for (const result of resolveVersion(shallow)) {
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Full Git history/);
  }
  for (const result of resolveVersion(shallow, 'v2.3.4')) {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), 'v2.3.4');
  }
  const automatic = prepare('release.yml', {});
  assert.equal(automatic.status, 0, automatic.stderr);
  assert.equal(automatic.outputs.version, auto);
  const stale = prepare('release.yml', { INPUT_VERSION: 'v9.9.9', PUBLISH_RELEASE: 'true' });
  assert.notEqual(stale.status, 0);
  assert.match(stale.stdout, /Existing release tag points to another commit/);
  for (const inputs of [{ INPUT_VERSION: 'v9.9.9', PUBLISH_RELEASE: 'false' }, { INPUT_VERSION: 'v9.9.8', PUBLISH_RELEASE: 'true' }]) {
    const result = prepare('release.yml', inputs);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.outputs.version, inputs.INPUT_VERSION);
  }
  for (const [flag, expected] of [['', 'true'], ['true', 'true'], ['false', 'false']]) {
    const result = prepare('openwrt-feed.yml', { PUBLISH_FEED: flag });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.outputs.publish_feed, expected);
    assert.equal(result.outputs.version, auto);
  }
  const tagged = prepare('openwrt-feed.yml', { GITHUB_REF: 'refs/tags/v9.9.8', GITHUB_REF_NAME: 'v9.9.8' });
  assert.equal(tagged.outputs.version, 'v9.9.8');
  const override = prepare('openwrt-feed.yml', { INPUT_VERSION: '1.2.3', GITHUB_REF: 'refs/tags/v9.9.8', GITHUB_REF_NAME: 'v9.9.8' });
  assert.equal(override.outputs.version, 'v1.2.3');
  console.log('Bash/PowerShell versioning, shallow-history, source-ref, override and workflow preparation checks passed');
} finally {
  // Check the exact resolved target before recursively deleting this fixture.
  assert.equal(path.dirname(path.resolve(temp)), path.resolve(os.tmpdir()));
  assert.ok(path.basename(temp).startsWith('p2ptap-version-'));
  fs.rmSync(temp, { recursive: true, force: true });
}
