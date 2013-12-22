var bindings = require('bindings')('scrypt.node')

module.exports = function scrypt(data, salt, N, r, p, len, callback) {
	if (N < 2 || (N & (N - 1)) !== 0) {
		throw new Error('N must be a power of 2')
	}
	if (r < 1) {
		throw new Error('r must be > 0')
	}
	if (p < 1) {
		throw new Error('p must be > 0')
	}
	if (len < 1) {
		throw new Error('len must be > 0')
	}
	return bindings.scrypt(data, salt, N, r, p, len, callback)
}
