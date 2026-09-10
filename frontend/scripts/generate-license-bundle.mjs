import { copyFile, cp, mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const frontendRoot = resolve(scriptDirectory, '..')
const repositoryRoot = resolve(frontendRoot, '..')
const outputRoot = resolve(frontendRoot, 'dist', 'legal')
const npmOutputRoot = join(outputRoot, 'npm')
const licensePattern = /^(licen[cs]e|copying|notice)([._-].*)?$/i
const repositoryLegalFiles = [
  'AGENTS.md',
  'LICENSE',
  'NOTICE.md',
  'THIRD_PARTY_NOTICES.md',
  'SUPPORT.md',
  'SUPPORT.zh-CN.md',
  'COMMERCIAL_SERVICES.md',
  'COMMERCIAL_SERVICES.zh-CN.md',
  'CLA_POLICY.md',
  'CLA_POLICY.zh-CN.md',
  'CONTRIBUTING.md',
  'CONTRIBUTING.zh-CN.md',
  'SECURITY.md',
]

const packageLock = JSON.parse(await readFile(join(frontendRoot, 'package-lock.json'), 'utf8'))
const productionPackages = Object.entries(packageLock.packages)
  .filter(([packagePath, metadata]) => packagePath && metadata.version && !metadata.dev)
  .sort(([left], [right]) => left.localeCompare(right))

await mkdir(npmOutputRoot, { recursive: true })
for (const filename of repositoryLegalFiles) {
  await copyFile(join(repositoryRoot, filename), join(outputRoot, filename))
}
await copyFile(join(repositoryRoot, 'LICENSE'), join(outputRoot, 'AGPL-3.0-only.txt'))
await cp(join(repositoryRoot, 'third_party'), join(outputRoot, 'third_party'), { recursive: true })
await mkdir(join(outputRoot, 'docs', 'legal'), { recursive: true })
await copyFile(
  join(repositoryRoot, 'docs', 'legal', 'dependency-compliance.md'),
  join(outputRoot, 'docs', 'legal', 'dependency-compliance.md'),
)

const index = [
  '# Bundled npm license files',
  '',
  'Generated from package-lock.json. Package authors retain all rights in their notices.',
  '',
]

for (const [packagePath, metadata] of productionPackages) {
  let licenseSourceDirectory = join(frontendRoot, packagePath)
  const packageName = packagePath.slice(packagePath.lastIndexOf('node_modules/') + 13)
  const destinationDirectory = join(npmOutputRoot, packagePath.replaceAll('node_modules/', ''))
  const entries = await readdir(licenseSourceDirectory, { withFileTypes: true })
  let licenseFiles = entries
    .filter((entry) => entry.isFile() && licensePattern.test(entry.name))
    .map((entry) => entry.name)
    .sort()

  if (licenseFiles.length === 0) {
    licenseSourceDirectory = join(
      repositoryRoot,
      'third_party',
      'npm',
      packageName,
      metadata.version,
    )
    const fallbackEntries = await readdir(licenseSourceDirectory, { withFileTypes: true }).catch(
      () => [],
    )
    licenseFiles = fallbackEntries
      .filter((entry) => entry.isFile() && licensePattern.test(entry.name))
      .map((entry) => entry.name)
      .sort()
  }

  index.push(`- ${packageName}@${metadata.version} — ${metadata.license ?? 'license metadata absent'}`)
  if (licenseFiles.length === 0) {
    throw new Error(
      `No license/notice file found for production package ${packageName}@${metadata.version}`,
    )
  }

  await mkdir(destinationDirectory, { recursive: true })
  for (const filename of licenseFiles) {
    await copyFile(
      join(licenseSourceDirectory, filename),
      join(destinationDirectory, basename(filename)),
    )
    index.push(`  - ${packagePath.replaceAll('node_modules/', '')}/${filename}`)
  }
}

await writeFile(join(npmOutputRoot, 'INDEX.md'), `${index.join('\n')}\n`, 'utf8')
