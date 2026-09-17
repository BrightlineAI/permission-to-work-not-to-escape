const add = (left: number, right: number): number => left + right;
if (add(20, 22) !== 42) throw new Error('wrong sum');
console.log('TYPESCRIPT_BUILD_OK 42');
