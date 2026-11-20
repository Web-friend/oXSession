'use strict'

const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')

const packageDir = path.resolve(__dirname, '..')
const repoRoot = path.resolve(packageDir, '../..')
execFileSync('cargo', ['build', '--release', '--manifest-path', path.join(packageDir, 'Cargo.toml')], {
  cwd: repoRoot,
  stdio: 'inherit',
})

const candidates = process.platform === 'win32'
  ? ['oxsession_node.dll']
  : process.platform === 'darwin'
    ? ['liboxsession_node.dylib']
    : ['liboxsession_node.so']
const source = candidates
  .map((file) => path.join(repoRoot, 'target', 'release', file))
  .find((file) => fs.existsSync(file))

if (!source) throw new Error(`could not find built native library for ${process.platform}`)
fs.copyFileSync(source, path.join(packageDir, 'oxsession.node'))
