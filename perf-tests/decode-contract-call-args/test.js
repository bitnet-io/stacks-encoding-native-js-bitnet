const sen = require('../..');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

/*
const gzipped = zlib.gzipSync(fs.readFileSync(path.join(__dirname, 'sampled-contract-call-args.txt')));
fs.writeFileSync(path.join(__dirname, `sampled-contract-call-args.txt.gz`), gzipped);
process.exit();
*/

function getSampleInput() {
    const inputFilePath = path.join(__dirname, 'sampled-contract-call-args.txt.gz');
    const decompressedInput = zlib.gunzipSync(fs.readFileSync(inputFilePath)).toString('utf8');
    const lines = decompressedInput.split('\n');
    return lines.filter(r => !!r).map(r => Buffer.from(r, 'hex'));
}

const buffers = getSampleInput();
global.gc();

sen.startProfiler();

const startTime = Date.now();
let totalLen = 0;
const rounds = 100;
for (let i = 0; i < rounds; i++) {
    if (i % 10 === 0) {
        console.log(`${Math.round(i / rounds * 100)}%`);
    }
    for (const buf of buffers) {
        const decoded = sen.decodeClarityValueList(buf);
        // do something with results so JIT doesn't do anything weird like optimize away something
        totalLen += decoded.map(d => d.hex.length).reduce((p, d) => p + d, 0);
    }
}

const elapsed = Math.round((Date.now() - startTime) / 10) / 100;
const profile = sen.stopProfiler();

const outputFile = path.join(__dirname, 'results', `profile-${Date.now()}-${elapsed}s.svg`);
fs.mkdirSync(path.dirname(outputFile), { recursive: true });
fs.writeFileSync(outputFile, profile);

console.log(`Took ${elapsed} seconds`);
console.log(`Output: ${outputFile}`);
