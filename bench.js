var scrypt = require('./')

var data = Buffer.from('f84913e3d8e6d624689d0a3e9678ac8dcc79d2c2f3d9641488cd9d6ef6cd83dd', 'hex')
var salt = Buffer.from('identity.mozilla.com/picl/v1/scrypt')
var buf = '5b82f146a64126923e4167a0350bb181feba61f63cb1714012b19cb0be0119c5'
var x = 100

function loop(err, hash) {
	if (hash.toString('hex') !== buf) {
		console.error('oops')
	}
	if (--x > 0) {
		scrypt(data, salt, 65536, 8, 1, 32, loop)
	}
	else if (x === 0) {
		console.timeEnd('loop')
	}
}
console.time('loop')
for (var i = 0; i < 10; i++) {
	loop(null, Buffer.from(buf, 'hex'))
}
