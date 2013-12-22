var scrypt = require('./')

var K1 = Buffer('f84913e3d8e6d624689d0a3e9678ac8dcc79d2c2f3d9641488cd9d6ef6cd83dd', 'hex')
var salt = Buffer('identity.mozilla.com/picl/v1/scrypt')

console.time('native')
scrypt(
	K1,
	salt,
	1024 * 64,
	8,
	1,
	32,
	function (err, K2) {
		console.timeEnd('native')
		if (K2.toString('hex') === '5b82f146a64126923e4167a0350bb181feba61f63cb1714012b19cb0be0119c5') {
			console.log('YAY!')
		}
		else {
			console.log('BOO!')
		}
	}
)
