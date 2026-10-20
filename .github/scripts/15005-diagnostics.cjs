const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');

const observationMs = 90000;

function hasGuard(logs) {
  return /"id"\s*:\s*12257600\b/.test(logs);
}

function classify(result) {
  if (result.infrastructureError || result.collectionError) return 'Infrastructure/collection error; inconclusive';
  if (hasGuard(result.logs)) {
    return 'SERVER-121912 startup guard triggered; actual kernel defect not established';
  }
  if (result.error) return 'Runtime/connectivity failure; inspect logs, not attributed to rseq';
  if (result.elapsedMs >= observationMs && result.operations > 0 &&
      result.state.Running && result.restartCount === 0) {
    return 'Passed 90-second CRUD observation; no failure observed';
  }
  return 'Incomplete observation; inconclusive';
}

function comparison(results) {
  const old = results.find(result => result.label === '8.3.13');
  const updated = results.find(result => result.label === '8.3.14');
  if (!old || !updated || old.infrastructureError || updated.infrastructureError ||
      old.collectionError || updated.collectionError) {
    return 'Pinned comparison incomplete; no kernel attribution is possible.';
  }
  const passed = result => classify(result).startsWith('Passed');
  if (hasGuard(old.logs) && passed(updated)) {
    return '8.3.13 was blocked by the SERVER-121912 guard, while 8.3.14 passed on the same VM. ' +
      'This supports the Ubuntu kernel-version detection issue SERVER-131779, not proof of ' +
      'an unfixed kernel rseq defect. Confirm kernel patch provenance before declaring compatibility.';
  }
  if (hasGuard(old.logs) && hasGuard(updated.logs)) {
    return 'Both pinned versions triggered the compatibility guard. Verify the upstream kernel ' +
      'version and Ubuntu/Azure backports; a version gate alone does not demonstrate the rseq defect.';
  }
  if (passed(old) && passed(updated)) {
    return 'Both pinned versions passed; the reported failure was not reproduced on this VM.';
  }
  return 'Results do not isolate the known version-gate issue. Inspect runtime errors and raw evidence; ' +
    'do not attribute a crash to rseq without a matching stack trace or kernel patch evidence.';
}

async function main() {
  const { MongoClient } = require('mongodb');
  const directory = process.env.DIAGNOSTICS_DIR;
  fs.mkdirSync(directory, { recursive: true });
  let collectionFailed = false;
  function save(name, value) {
    fs.writeFileSync(path.join(directory, name), value);
  }
  function command(name, executable, args) {
    const result = spawnSync(executable, args, {
      encoding: 'utf8', timeout: 120000, maxBuffer: 16 * 1024 * 1024,
    });
    const output = `${result.stdout || ''}${result.stderr || ''}`;
    save(name, `$ ${executable} ${args.join(' ')}\nexit=${result.status}\n` +
      `${result.error ? `${result.error.stack}\n` : ''}${output}`);
    if (result.error || result.status !== 0) {
      console.error(`::warning::Diagnostic command failed: ${name}; see artifact`);
    }
    return { ...result, output };
  }
  function required(name, executable, args) {
    const result = command(name, executable, args);
    if (result.error || result.status !== 0) {
      throw new Error(`${name} failed: ${result.error?.message || result.output}`);
    }
    return result.stdout;
  }
  function inspect(container, name) {
    return JSON.parse(required(name, 'docker', ['inspect', container]))[0];
  }
  const metadata = {
    label: process.env.MATRIX_OS, imageOS: process.env.ImageOS,
    imageVersion: process.env.ImageVersion, node: process.version,
    observationMs, startedAt: new Date().toISOString(),
  };
  save('runner.json', JSON.stringify(metadata, null, 2));
  const kernel = command('host-uname.txt', 'uname', ['-a']).stdout?.trim();
  for (const file of ['/etc/os-release', '/proc/version', '/proc/version_signature']) {
    command(`host-${path.basename(file)}.txt`, 'cat', [file]);
  }
  const release = command('host-kernel-release.txt', 'uname', ['-r']).stdout?.trim();
  if (release) {
    const packageName = `linux-image-${release}`;
    command('kernel-package.txt', 'dpkg-query', ['-s', packageName]);
    command('kernel-package-policy.txt', 'apt-cache', ['policy', packageName]);
    command('kernel-package-files.txt', 'dpkg-query', ['-L', packageName]);
    command('kernel-package-source.txt', 'apt-cache', ['show', packageName]);
    command('kernel-local-changelog.txt', 'zcat', [
      `/usr/share/doc/${packageName}/changelog.Debian.gz`,
    ]);
  }
  command('docker-version.txt', 'docker', ['version']);
  command('docker-info.txt', 'docker', ['info']);
  command('host-listeners.txt', 'ss', ['-lntp']);
  command('host-routes.txt', 'ip', ['route']);
  command('host-nat.txt', 'sudo', ['iptables', '-t', 'nat', '-L', '-n', '-v']);
  command('host-dmesg.txt', 'sudo', ['dmesg', '--ctime']);

  const results = [];
  for (const label of ['service-mongo-8', '8.3.13', '8.3.14']) {
    const result = { label, operations: 0, elapsedMs: 0, logs: '', state: {}, restartCount: null };
    const prefix = label.replaceAll('.', '-');
    let container;
    let owned = false;
    let phase = 'infrastructure';
    try {
      if (label === 'service-mongo-8') {
        container = process.env.MONGO_CONTAINER;
        if (!container) throw new Error('MONGO_CONTAINER is required');
      } else {
        const image = `mongo:${label}`;
        required(`${prefix}-pull.txt`, 'docker', ['pull', image]);
        container = required(`${prefix}-create.txt`, 'docker', [
          'create', '--publish', '127.0.0.1::27017', image,
        ]).trim();
        owned = true;
        required(`${prefix}-start.txt`, 'docker', ['start', container]);
      }
      const initial = inspect(container, `${prefix}-inspect-before.txt`);
      result.imageID = initial.Image;
      result.configuredImage = initial.Config.Image;
      result.environment = initial.Config.Env;
      result.healthcheck = initial.Config.Healthcheck || null;
      required(`${prefix}-image-inspect.txt`, 'docker', ['image', 'inspect', initial.Image]);
      command(`${prefix}-binary-version.txt`, 'docker', [
        'run', '--rm', '--entrypoint', 'mongod', initial.Image, '--version',
      ]);
      // A shell-only helper collects the container's kernel view even when mongod exits immediately.
      command(`${prefix}-container-kernel.txt`, 'docker', [
        'run', '--rm', '--entrypoint', 'sh', initial.Image, '-c',
        'uname -a; cat /proc/version; cat /proc/version_signature',
      ]);
      phase = 'runtime';
      if (!initial.State.Running) throw new Error('Container exited before the observation');
      const binding = initial.NetworkSettings.Ports['27017/tcp']?.[0];
      // An exited service may already have lost its port bindings.
      const port = binding?.HostPort || (label === 'service-mongo-8' ? '27017' : null);
      if (!port) throw new Error('No published MongoDB port found');
      const client = new MongoClient(`mongodb://127.0.0.1:${port}/repro15005`, {
        serverSelectionTimeoutMS: 10000, connectTimeoutMS: 10000,
        socketTimeoutMS: 10000,
      });
      const events = [];
      let started;
      try {
        await client.connect();
        const db = client.db();
        result.buildInfo = await db.admin().command({ buildInfo: 1 });
        const parameters = await db.admin().command({ getParameter: '*' });
        save(`${prefix}-server-parameters.json`, JSON.stringify(parameters, null, 2));
        const collection = db.collection('observation');
        started = Date.now();
        do {
          const value = result.operations;
          await db.command({ ping: 1 });
          await collection.insertOne({ _id: value, value });
          await collection.updateOne({ _id: value }, { $inc: { value: 1 } });
          const document = await collection.findOne({ _id: value });
          if (document?.value !== value + 1) throw new Error('CRUD read verification failed');
          const deletion = await collection.deleteOne({ _id: value });
          if (deletion.deletedCount !== 1) throw new Error('CRUD delete verification failed');
          result.operations++;
          result.elapsedMs = Date.now() - started;
          events.push({ elapsedMs: result.elapsedMs, operation: value, ok: true });
          await delay(1000);
        } while (Date.now() - started < observationMs);
        await db.command({ ping: 1 });
        result.elapsedMs = Date.now() - started;
        save(`${prefix}-server-status.json`, JSON.stringify(
          await db.admin().command({ serverStatus: 1 }), null, 2));
      } finally {
        if (started !== undefined) result.elapsedMs = Date.now() - started;
        save(`${prefix}-operations.json`, JSON.stringify(events, null, 2));
        await client.close();
      }
    } catch (error) {
      result.error = error.stack;
      result.infrastructureError = phase === 'infrastructure';
      console.error(`${label}: ${error.stack}`);
    } finally {
      if (container) {
        const logs = command(`${prefix}-container-logs.txt`, 'docker', [
          'logs', '--timestamps', container,
        ]);
        result.logs = logs.output;
        if (logs.error || logs.status !== 0) {
          collectionFailed = true;
          result.collectionError = 'Container logs could not be collected';
        }
        try {
          const final = inspect(container, `${prefix}-inspect-after.txt`);
          result.state = final.State;
          result.restartCount = final.RestartCount;
        } catch (error) {
          collectionFailed = true;
          console.error(error.stack);
          result.collectionError = error.stack;
        }
        if (owned) {
          const cleanup = command(`${prefix}-cleanup.txt`, 'docker', ['rm', '--force', '--volumes', container]);
          if (cleanup.error || cleanup.status !== 0) collectionFailed = true;
        }
      }
    }
    result.verdict = classify(result);
    results.push(result);
    save('results.json', JSON.stringify(results, null, 2));
  }
  command('host-dmesg-after.txt', 'sudo', ['dmesg', '--ctime']);
  const summary = [
    `## MongoDB / ${metadata.label}`,
    '',
    `Image: ${metadata.imageVersion}; kernel: ${kernel}`,
    '',
    '| Case | Observed build | CRUD cycles | Observed seconds | Exit / running | Verdict |',
    '|---|---|---:|---:|---|---|',
    ...results.map(result => `| ${result.label} | ${result.buildInfo?.version || 'Not obtained'} | ` +
      `${result.operations} | ${(result.elapsedMs / 1000).toFixed(1)} | ` +
      `${result.state.ExitCode ?? '?'} / ${result.state.Running ?? '?'} | ${result.verdict} |`),
    '',
    comparison(results),
    '',
    'A fatal 12257600 identifies the startup guard, not an observed rseq crash. ' +
      'Ubuntu ABI suffixes are not upstream patch levels. Check host/container version_signature ' +
      'and package provenance before claiming that the Azure kernel lacks a fix.',
    '',
    'The original service uses its published port 27017; pinned containers use dynamically ' +
      'published loopback ports on the same VM. Each pinned container has fresh data. ' +
      'No healthcheck, rseq environment override, or kernel workaround is added.',
    '',
    'Passing this bounded observation does not prove absence of corruption or full compatibility.',
    '',
    'References: [SERVER-121912](https://jira.mongodb.org/browse/SERVER-121912), ' +
      '[SERVER-125742](https://jira.mongodb.org/browse/SERVER-125742), ' +
      '[SERVER-131779](https://jira.mongodb.org/browse/SERVER-131779).',
    '',
    collectionFailed ? '**Evidence collection or cleanup failed; inspect diagnostic command exit codes.**' : '',
  ].join('\n');
  save('summary.md', summary);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
  console.log(summary);
  if (collectionFailed || results.some(result => !result.verdict.startsWith('Passed'))) {
    process.exitCode = 1;
  }
}

module.exports = { hasGuard, classify, comparison };
if (require.main === module) {
  main().catch(error => {
    console.error(error.stack);
    process.exitCode = 1;
  });
}
