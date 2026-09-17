import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {add} from '@fixture/math';
const require = createRequire(import.meta.url);
assert.equal(add(20, 22), 42);
assert.equal(require('@fixture/math').add(21, 21), 42);
console.log('Workspace ESM and CommonJS imports passed');
