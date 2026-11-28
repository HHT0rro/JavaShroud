import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone

BASE = pathlib.Path(os.environ['GITHUB_WORKSPACE'])
INPUT = BASE / 'workflow/.github/rc4-jvm-validation'
SOURCE = BASE / 'product'
EVIDENCE = BASE / 'hosted-evidence'
COMMIT = 'eca01095f7a945e2651e24eb0bd9f849d5f2c408'
VERSION = '0.31.2-rc.4'
EXPECTED_ARCHIVE_SHA = '8160961e01d55d97fde45eb310332ae3e32b08e216357f688fc816edb3c577f9'
EVIDENCE.mkdir()
UNPACK_INPUT = BASE / 'verification-input'
UNPACK_INPUT.mkdir()
commands = []


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def bound(path):
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def run(name, args, expected=0, cwd=BASE, env=None):
    started = datetime.now(timezone.utc).isoformat()
    stdout = EVIDENCE / (name + '.stdout.log')
    stderr = EVIDENCE / (name + '.stderr.log')
    with stdout.open('wb') as out, stderr.open('wb') as err:
        result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, stdout=out, stderr=err, timeout=240)
    record = {'name': name, 'argv': list(map(str, args)), 'cwd': str(cwd), 'started_at': started,
              'ended_at': datetime.now(timezone.utc).isoformat(), 'exit': result.returncode,
              'expected_exit': expected, 'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}
    commands.append(record)
    save(EVIDENCE / 'commands.json', commands)
    assert result.returncode == expected, record
    print(json.dumps({'check': name, 'exit': result.returncode}), flush=True)
    return stdout.read_text(), stderr.read_text()


bundle = INPUT / 'validation-input.zip'
expected_bundle = json.loads((INPUT / 'input-binding.json').read_text())
assert sha(bundle) == expected_bundle['sha256'] and bundle.stat().st_size == expected_bundle['bytes']
with zipfile.ZipFile(bundle) as archive:
    assert archive.testzip() is None
    for info in archive.infolist():
        assert not pathlib.PurePosixPath(info.filename).is_absolute()
        assert '..' not in pathlib.PurePosixPath(info.filename).parts
    archive.extractall(UNPACK_INPUT)
input_files = json.loads((UNPACK_INPUT / 'input-files.json').read_text())
for row in input_files:
    path = UNPACK_INPUT / row['path']
    assert path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], row
product_head = subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], text=True).strip()
product_tree = subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
assert product_head == COMMIT and product_tree == '69bf3edff1fa87f034b97728d572eaae96d29a64'
manifest = json.loads((UNPACK_INPUT / 'source-files.json').read_text())
assert len(manifest) == 784
for row in manifest:
    path = SOURCE / row['path']
    assert path.stat().st_size == row['size'] and sha(path) == row['sha256'], row
save(EVIDENCE / 'source-final-verification.json', {'checked': len(manifest), 'mismatches': [],
     'source_commit': COMMIT, 'source_tree': product_tree, 'location': 'Independent hosted checkout after local build'})
archive = UNPACK_INPUT / 'javashroud-core-engine-v0.31.2-rc.4-Linux-x86_64-JVM.tar.gz'
assert archive.stat().st_size == 66950463 and sha(archive) == EXPECTED_ARCHIVE_SHA
uncompressed_size = 0
with gzip.open(archive, 'rb') as stream:
    while block := stream.read(1024 * 1024):
        uncompressed_size += len(block)
unpack = BASE / 'package'
unpack.mkdir()
file_rows = []
with tarfile.open(archive, 'r:gz') as tar:
    members = tar.getmembers()
    assert len({item.name for item in members}) == len(members)
    for member in members:
        assert not member.name.startswith('/') and '..' not in pathlib.PurePosixPath(member.name).parts
        assert member.isfile() or member.isdir()
    tar.extractall(unpack, filter='data')
    for member in members:
        if member.isfile():
            data = tar.extractfile(member).read()
            file_rows.append({'path': member.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                              'mode': oct(member.mode & 0o7777)})
assert len(file_rows) == 51
app = unpack / ('core-engine-' + VERSION)
engine = app / 'lib' / ('obfuscator-engine-' + VERSION + '.jar')
original_files = json.loads((UNPACK_INPUT / 'raw-unpacked-files.json').read_text())
assert len(original_files) == 45
for row in original_files:
    path = app / row['path']
    assert path.is_file() and sha(path) == row['sha256']
    assert stat.S_IMODE(path.stat().st_mode) == int(row['mode'], 8)
for name in ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'README.md', 'README_EN.md']:
    assert (app / name).read_bytes() == (SOURCE / name).read_bytes()
assert COMMIT in (app / 'README-JVM.txt').read_text()
assert stat.S_IMODE((app / 'bin/core-engine').stat().st_mode) == 0o755
native = EVIDENCE / 'libqp_ffi.so'
rust_prefix = 'core-engine/src/main/rust/'
rust_sources = {row['path'].removeprefix(rust_prefix): row for row in manifest if row['path'].startswith(rust_prefix)}
with zipfile.ZipFile(engine) as jar:
    assert jar.testzip() is None
    assert b'Implementation-Version: 0.31.2-rc.4' in jar.read('META-INF/MANIFEST.MF')
    native_entries = [name for name in jar.namelist() if name.startswith('META-INF/jsrt/') and not name.endswith('/')]
    assert native_entries == ['META-INF/jsrt/linux-x64/libqp_ffi.so']
    native.write_bytes(jar.read(native_entries[0]))
    embedded = {name.removeprefix('META-INF/rust-runtime/') for name in jar.namelist()
                if name.startswith('META-INF/rust-runtime/') and not name.endswith('/')}
    assert embedded == set(rust_sources) | {'file-list.txt'}
    assert set(jar.read('META-INF/rust-runtime/file-list.txt').decode().splitlines()) == set(rust_sources)
    for name, row in rust_sources.items():
        data = jar.read('META-INF/rust-runtime/' + name)
        assert len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256']
assert sha(native) == '9e65ef7d7a6249392cc11e4b0556888b1e8b91957d5948bd8334fdc6b7577b61'
probe = UNPACK_INPUT / 'probe'
probe_binding = json.loads((UNPACK_INPUT / 'probe-source-binding.json').read_text())
probe_source = SOURCE / probe_binding['source_path'].replace('\\', '/')
assert sha(probe_source) == probe_binding['source_sha256']
body = probe_source.read_text()
object_text = body[body.index('internal object QpBridgeProbe {'):]
assert hashlib.sha256(object_text.encode()).hexdigest() == probe_binding['extracted_object_sha256']
probe_class = probe / 'io/github/hht0rro/javashroud/QpBridgeProbe.class'
raw_result = json.loads((UNPACK_INPUT / 'raw-ubuntu-validation.json').read_text())
assert sha(probe_class) == raw_result['probe_class_sha256']
fixture = EVIDENCE / 'fixture'
fixture.mkdir()
calc = SOURCE / 'core-engine/src/test/resources/official-test-jar/pack/tests/bench/Calc.java'
shutil.copyfile(calc, fixture / 'Calc.java')
main = fixture / 'OwnedCalcMain.java'
main.write_text('public final class OwnedCalcMain { public static void main(String[] args) { pack.tests.bench.Calc.runAll(); System.out.println("COUNT=" + pack.tests.bench.Calc.count); } }\n')
classes = fixture / 'classes'
classes.mkdir()
jdk21 = pathlib.Path(os.environ.get('JVM21_HOME') or os.environ['JAVA_HOME'])
run('fixture-compile', [jdk21 / 'bin/javac', '-J-Xmx128m', '-J-XX:ActiveProcessorCount=2', '--release', '8', '-g', '-d', classes, fixture / 'Calc.java', main])
input_jar = fixture / 'original.jar'
run('fixture-jar', [jdk21 / 'bin/jar', '-J-Xmx128m', '-J-XX:ActiveProcessorCount=2', '--create', '--file', input_jar, '--main-class', 'OwnedCalcMain', '-C', classes, '.'])
fixture_sha = sha(input_jar)
runtime_results = []
for label, home in [('jdk17', pathlib.Path(os.environ['JVM17_HOME'])), ('jdk21', jdk21)]:
    env = os.environ.copy()
    env['JAVA_HOME'] = str(home)
    env['PATH'] = str(home / 'bin') + os.pathsep + env['PATH']
    env['JAVA_OPTS'] = '-Xmx256m -XX:ActiveProcessorCount=2'
    for key in ['JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'GH_TOKEN']:
        env.pop(key, None)
    version, version_err = run(label + '-version', [home / 'bin/java', '-version'], env=env)
    schema, err = run(label + '-schema', [app / 'bin/core-engine', '-schema'], env=env)
    assert "schemaVersion = '2'" in schema and "engineVersion = '0.31.2-rc.4'" in schema and not err
    stdout, err = run(label + '-jni', [home / 'bin/java', '-Xmx256m', '-XX:ActiveProcessorCount=2', '-cp', str(probe) + ':' + str(app / 'lib/*'), 'io.github.hht0rro.javashroud.QpBridgeProbe', native, 'linux-x64'], env=env)
    assert stdout.splitlines() == ['INIT=0', 'BEAT=0', 'SESSION=ok', 'UNBOUND=ok'] and not err
    original, err = run(label + '-original', [home / 'bin/java', '-Xmx256m', '-XX:ActiveProcessorCount=2', '-jar', input_jar], env=env)
    assert 'COUNT=30000' in original and not err
    output = EVIDENCE / (label + '-minimal.jar')
    config = EVIDENCE / (label + '-minimal.toml')
    config_text = 'inputJarPath = ' + json.dumps(str(input_jar)) + '\noutputJarPath = ' + json.dumps(str(output)) + '\nprotectionProfile = "minimal"\n\n[[passes]]\nid = "strip-compile-debug-info"\nenabled = true\n'
    config.write_text(config_text)
    stdout, err = run(label + '-strip', [app / 'bin/core-engine', '-config', config], env=env)
    assert 'passes=1' in stdout and not err
    processed, err = run(label + '-processed', [home / 'bin/java', '-Xmx256m', '-XX:ActiveProcessorCount=2', '-jar', output], env=env)
    assert 'COUNT=30000' in processed and not err
    majors = {}
    with zipfile.ZipFile(output) as jar:
        assert jar.testzip() is None
        for name in jar.namelist():
            if name.endswith('.class'):
                data = jar.read(name)
                majors[name] = struct.unpack_from('>H', data, 6)[0]
                assert b'LineNumberTable' not in data and b'LocalVariableTable' not in data
    assert set(majors.values()) == {52}
    collision = EVIDENCE / (label + '-collision.toml')
    collision.write_text(config_text.replace(json.dumps(str(output)), json.dumps(str(input_jar))))
    stdout, err = run(label + '-collision', [app / 'bin/core-engine', '-config', collision], expected=1, env=env)
    assert 'Output or sidecar path refers to a protected run file' in err
    assert sha(input_jar) == fixture_sha
    runtime_results.append({'jdk': label, 'java_version': version + version_err, 'launcher_exit': 0, 'jni_exit': 0,
         'schema_version': 2, 'engine_version': VERSION, 'jni_markers': ['INIT=0', 'BEAT=0', 'SESSION=ok', 'UNBOUND=ok'],
         'profile': 'explicit minimal', 'passes': 1, 'original_count': 30000, 'processed_count': 30000,
         'processed_classfile_majors': majors, 'input_sha256_before': fixture_sha, 'input_sha256_after': sha(input_jar),
         'collision_exit': 1, 'output_sha256': sha(output)})
version_info, err = run('native-glibc-symbols', ['readelf', '--version-info', native])
versions = sorted(set(re.findall(r'GLIBC_(\d+(?:\.\d+)+)', version_info)), key=lambda value: tuple(map(int, value.split('.'))))
assert versions[-1] == '2.17'
ldd, err = run('native-ldd', ['ldd', native])
assert 'not found' not in ldd
tools = EVIDENCE / 'centos7-toolchain'
tools.mkdir()
jdk_tar = tools / 'OpenJDK21U-jdk_x64_linux_hotspot_21.0.4_7.tar.gz'
with jdk_tar.open('wb') as out:
    subprocess.run(['gh', 'api', '-H', 'Accept: application/octet-stream', 'repos/adoptium/temurin21-binaries/releases/assets/180159092'], stdout=out, check=True, timeout=180)
assert jdk_tar.stat().st_size == 207789015
assert sha(jdk_tar) == '51fb4d03a4429c39d397d3a03a779077159317616550e4e71624c9843083e7b9'
image = 'centos@sha256:be65f488b7764ad3638f236b7b515b3678369a5124c47b8d32916d6487418ea4'
run('centos-pull', ['docker', 'pull', '--platform=linux/amd64', image])
shutil.copyfile(UNPACK_INPUT / 'verify-centos7.sh', EVIDENCE / 'verify-centos7.sh')
shutil.copyfile(UNPACK_INPUT / 'verify-centos7-cli.sh', EVIDENCE / 'verify-centos7-cli.sh')
shutil.copyfile(input_jar, EVIDENCE / 'cli-original.jar')
shutil.copytree(probe, EVIDENCE / 'probe')
(EVIDENCE / 'native').mkdir()
shutil.copyfile(native, EVIDENCE / 'native/libqp_ffi.so')
run('centos-runtime', ['docker', 'run', '--rm', '--read-only', '--network=none', '--cpus=1', '--memory=768m', '--memory-swap=768m', '--tmpfs', '/tmp:rw,exec,size=640m',
    '--env', 'EXPECTED_ARCHIVE_SHA256=' + EXPECTED_ARCHIVE_SHA, '--env', 'EXPECTED_ENGINE_SHA256=' + sha(engine), '--env', 'EXPECTED_VERSION=' + VERSION,
    '--mount', 'type=bind,source=' + str(EVIDENCE) + ',target=/evidence', '--mount', 'type=bind,source=' + str(tools) + ',target=/tools,readonly',
    '--mount', 'type=bind,source=' + str(archive) + ',target=/package,readonly', image, 'bash', '/evidence/verify-centos7.sh'])
assert (EVIDENCE / 'centos7-calc-input-before.txt').read_text() == (EVIDENCE / 'centos7-calc-input-after.txt').read_text()
assert (EVIDENCE / 'centos7-calc-input-before.txt').read_text().split()[0] == fixture_sha
assert (EVIDENCE / 'centos7-jni-probe.stdout.log').read_text().splitlines() == ['INIT=0', 'BEAT=0', 'SESSION=ok', 'UNBOUND=ok']
assert 'release version 2.17' in (EVIDENCE / 'centos7-glibc.log').read_text()
centos_majors = {}
with zipfile.ZipFile(EVIDENCE / 'centos7-minimal.jar') as jar:
    assert jar.testzip() is None
    for name in jar.namelist():
        if name.endswith('.class'):
            data = jar.read(name)
            centos_majors[name] = struct.unpack_from('>H', data, 6)[0]
            assert b'LineNumberTable' not in data and b'LocalVariableTable' not in data
assert set(centos_majors.values()) == {52}
assert sha(archive) == EXPECTED_ARCHIVE_SHA
shutil.copyfile(archive, EVIDENCE / archive.name)
save(EVIDENCE / 'package-files.json', file_rows)
save(EVIDENCE / 'input-identity.json', {'bundle': bound(bundle), 'input_binding': expected_bundle,
     'product_commit': COMMIT, 'product_tree': product_tree, 'workflow_commit': os.environ['GITHUB_SHA']})
result = {'schema': 'javashroud-hosted-existing-linux-jvm-verification/v1', 'passed': True,
     'completed_at': datetime.now(timezone.utc).isoformat(), 'source_commit': COMMIT, 'product_tree': product_tree,
     'workflow_commit': os.environ['GITHUB_SHA'], 'workflow_ref': os.environ['GITHUB_REF'],
     'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
     'run_url': os.environ['GITHUB_SERVER_URL'] + '/' + os.environ['GITHUB_REPOSITORY'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID'],
     'package': {'name': archive.name, 'bytes': archive.stat().st_size, 'sha256': sha(archive)},
     'engine_jar_sha256': sha(engine), 'native_library_sha256': sha(native), 'native_max_glibc': versions[-1],
     'source_files_checked': len(manifest), 'embedded_rust_files_checked': len(rust_sources),
     'original_payload_files_matched': 45, 'final_regular_files': 51, 'launcher_permission_bits': '0o755',
     'gzip_crc_and_trailer_checked': True, 'uncompressed_stream_bytes': uncompressed_size,
     'ubuntu_runtime_checks': runtime_results,
     'centos7_glibc217_temurin21': {'passed': True, 'image': image, 'jdk_archive': bound(jdk_tar),
         'launcher_exit': 0, 'jni_exit': 0, 'schema_version': 2, 'engine_version': VERSION,
         'jni_markers': ['INIT=0', 'BEAT=0', 'SESSION=ok', 'UNBOUND=ok'], 'original_count': 30000,
         'processed_count': 30000, 'processed_classfile_majors': centos_majors, 'collision_exit': 1,
         'input_sha256_before': fixture_sha, 'input_sha256_after': fixture_sha},
     'new_product_build_performed': False, 'gradle_build_identity': 'Existing local eca0109 normal Gradle distTar, bound through supplied original build evidence',
     'hosted_scope': 'Independent verification of existing package bytes on Ubuntu24.04/JDK17/JDK21 and CentOS7/glibc2.17/Temurin21'}
save(EVIDENCE / 'verification.json', result)
shutil.rmtree(tools)
files = [path for path in EVIDENCE.rglob('*') if path.is_file() and path.name != 'SHA256SUMS']
(EVIDENCE / 'SHA256SUMS').write_text(''.join(sha(path) + '  ' + path.relative_to(EVIDENCE).as_posix() + '\n' for path in sorted(files)))
print(json.dumps(result, indent=2), flush=True)
