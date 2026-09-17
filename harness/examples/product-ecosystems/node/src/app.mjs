import assert from 'node:assert/strict';
import isNumber from 'is-number';

assert.equal(isNumber(20 + 22), true);
assert.equal(isNumber({value: 42}), false);
console.log('NODE_IMPORT_OK 42');
