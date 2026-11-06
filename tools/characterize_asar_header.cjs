'use strict';
// Original, read-only ASAR Pickle/JSON header observer. No extracted file text,
// path list, link target, credentials, or proprietary contents are published.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const MAX_HEADER = 32 * 1024 * 1024;
const MAX_ENTRIES = 500000;
const EXT = new Set(['.js', '.json', '.map', '.ts', '.css', '.html', '.wasm', '.node', '.png', '.svg', '.md', '.txt', '.mjs', '.cjs', '.bin', '.pak', '.db', '.sqlite']);
function hash(b) { return crypto.createHash('sha256').update(b).digest('hex'); }
function plainObject(v) { return !!v && typeof v === 'object' && !Array.isArray(v); }
function readAt(fd, length, offset) {
  const b = Buffer.alloc(length); let done = 0;
  while (done < length) { const n = fs.readSync(fd, b, done, length - done, offset + done); if (n === 0) throw Error('truncated ASAR'); done += n; }
  return b;
}
function inspect(file) {
  const fd = fs.openSync(file, 'r');
  let head, dataBytes, archiveSize;
  try {
    archiveSize = fs.fstatSync(fd).size;
    if (archiveSize < 16) throw Error('too-small ASAR');
    const sizePickle = readAt(fd, 8, 0);
    if (sizePickle.readUInt32LE(0) !== 4) throw Error('invalid header-size Pickle');
    const hSize = sizePickle.readUInt32LE(4);
    if (hSize < 8 || hSize > MAX_HEADER || hSize > archiveSize - 8) throw Error('ASAR header length out of bounds');
    const pickle = readAt(fd, hSize, 8);
    if (pickle.readUInt32LE(0) !== hSize - 4) throw Error('invalid ASAR Pickle payload length');
    const textLen = pickle.readUInt32LE(4);
    const padded = 4 + Math.ceil(textLen / 4) * 4;
    if (textLen < 2 || padded !== hSize - 4) throw Error('invalid JSON Pickle length');
    const jsonBytes = pickle.subarray(8, 8 + textLen);
    const json = JSON.parse(jsonBytes.toString('utf8'));
    if (!plainObject(json) || !plainObject(json.files)) throw Error('invalid root ASAR directory');
    dataBytes = archiveSize - 8 - hSize;
    const counters = { files: 0, packed: 0, unpacked: 0, links: 0, directories: 0, integrity: 0, max_depth: 0 };
    const extensions = Object.create(null);
    const todo = [{ files: json.files, depth: 1 }];
    while (todo.length) {
      const {files, depth} = todo.pop();
      if (depth > 64) throw Error('ASAR directory depth limit');
      counters.max_depth = Math.max(counters.max_depth, depth);
      for (const [name, entry] of Object.entries(files)) {
        if (++counters.files > MAX_ENTRIES) throw Error('ASAR entry count limit');
        if (!name || name === '.' || name === '..' || /[/\\\0]/.test(name)) throw Error('unsafe ASAR name');
        if (!plainObject(entry)) throw Error('invalid ASAR entry');
        if (Object.hasOwn(entry, 'files')) {
          if (!plainObject(entry.files)) throw Error('invalid ASAR subdirectory');
          counters.directories++; todo.push({ files: entry.files, depth: depth + 1 });
        } else if (Object.hasOwn(entry, 'link')) {
          if (typeof entry.link !== 'string' || !entry.link) throw Error('invalid ASAR link');
          counters.links++;
        } else {
          if (!Number.isSafeInteger(entry.size) || entry.size < 0) throw Error('invalid ASAR file length');
          if (entry.unpacked === true) counters.unpacked++;
          else {
            if (typeof entry.offset !== 'string' || !/^\d+$/.test(entry.offset)) throw Error('invalid ASAR file offset');
            const off = BigInt(entry.offset); const size = BigInt(entry.size);
            if (off + size > BigInt(dataBytes)) throw Error('ASAR data range exceeds archive');
            counters.packed++;
          }
          if (entry.integrity !== undefined) {
            if (!plainObject(entry.integrity) || entry.integrity.algorithm !== 'SHA256' || !/^[a-fA-F0-9]{64}$/.test(entry.integrity.hash || '')) throw Error('invalid ASAR integrity descriptor');
            counters.integrity++;
          }
          const match = /\.[^.]+$/.exec(name.toLowerCase());
          if (match && EXT.has(match[0])) extensions[match[0]] = (extensions[match[0]] || 0) + 1;
        }
      }
    }
    return {schema: 'cdr-asar-header-metadata/v1', evidence_grade: 'HEADER_INDEX_PARSED_NOT_CONTENTS_OR_STATE', archive_size_bytes: archiveSize, header_size_bytes: hSize, header_sha256: hash(pickle), entry_count: counters.files, directory_count: counters.directories, packed_file_count: counters.packed, unpacked_file_count: counters.unpacked, symlink_count: counters.links, integrity_descriptor_count: counters.integrity, max_depth: counters.max_depth, recognized_extensions: extensions, raw_paths_or_contents_published: false, decoder_roundtrip_verified: false, application_state_verified: false};
  } finally { fs.closeSync(fd); }
}
function makeSynthetic(header, data = 'abc') {
  const json = Buffer.from(JSON.stringify(header));
  const payloadLength = 4 + Math.ceil(json.length / 4) * 4;
  const pickle = Buffer.alloc(4 + payloadLength);
  pickle.writeUInt32LE(payloadLength, 0); pickle.writeUInt32LE(json.length, 4); json.copy(pickle, 8);
  const sizePickle = Buffer.alloc(8); sizePickle.writeUInt32LE(4, 0); sizePickle.writeUInt32LE(pickle.length, 4);
  return Buffer.concat([sizePickle, pickle, Buffer.from(data)]);
}
function selfTest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asar-source-known-'));
  const p = path.join(dir, 'fixture.asar');
  try {
    const hdr = {files: {'a.json': {offset:'0',size:3}, 'b.bin':{offset:'0',size:3}, 'unpacked.node':{unpacked:true,size:5}, 'L':{link:'a.json'}, 'sub':{files:{'c.js':{offset:'0',size:3}}}}};
    const buf = makeSynthetic(hdr); fs.writeFileSync(p, buf);
    const r = inspect(p);
    assert.equal(r.packed_file_count, 3); assert.equal(r.unpacked_file_count, 1); assert.equal(r.symlink_count, 1);
    assert.equal(r.recognized_extensions['.json'], 1); assert.equal(r.entry_count, 6);
    assert.equal(r.decoder_roundtrip_verified, false);
    function refuse(bytes) { fs.writeFileSync(p, bytes); assert.throws(() => inspect(p)); }
    const wrongSize = Buffer.from(buf); wrongSize.writeUInt32LE(0x7fffffff,4); refuse(wrongSize);
    refuse(makeSynthetic({files:{'unsafe/name':{offset:'0',size:3}}}));
    refuse(makeSynthetic({files:{'bad.js':{offset:'4',size:3}}}));
    refuse(makeSynthetic({files:{'bad.js':{offset:'0',size:-1}}}));
    refuse(makeSynthetic({files:{'bad.js':{offset:'0',size:3,integrity:{algorithm:'MD5',hash:'x'}}}}));
    console.log('ASAR_SOURCE_KNOWN_SELF_TEST_PASS (1 positive, 5 negatives)');
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
}
if (require.main === module) {
  try {
    if (process.argv.length === 3 && process.argv[2] === '--self-test') selfTest();
    else if (process.argv.length === 3) console.log(JSON.stringify(inspect(process.argv[2])));
    else throw Error('usage: node characterize_asar_header.cjs --self-test | <archive.asar>');
  } catch(e) { console.error('ASAR_CLASSIFICATION_FAILED: '+e.message); process.exitCode=1; }
}
module.exports = {inspect};
