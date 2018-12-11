# scrypt-hash

node bindings for crypto_scrypt from [scrypt](http://www.tarsnap.com/scrypt.html)

[![Build Status](https://travis-ci.org/dannycoates/scrypt-hash.png)](https://travis-ci.org/dannycoates/scrypt-hash)

# Example

```js
var scrypt = require('scrypt-hash')

var password = Buffer.from('aprettybadpassword')
var salt = Buffer.from('adashofsalt', 'utf8')
var N = 1024 * 64
var r = 8
var p = 1
var len = 32

scrypt(password, salt, N, r, p, len, function (err, hash) {
	if (err) {
		return console.error(err)
	}
	console.assert(hash.length === len)
	console.log('The hashed password is', hash.toString('hex'))
})
```

## scrypt(data, salt, N, r, p, len, callback)

### Arguments

* data - *Buffer* - the value you want to hash
* salt - *Buffer*
* N - *Number* - must be 32bit integer and a power of 2
* r - *Number*
* p - *Number*
* len - *Number* - length of the returned hash
* callback - *function (err, hash)*
    * err - *Error*
    * hash - *Buffer*

For info on what N, r, p do see http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-5

## Versioning

Major and Minor version numbers follow the scrypt C source. The Patch number of this library may differ from the upstream version as changes to either will increment this one.

## License

BSD 2-Clause, Copyright 2013 Danny Coates

scrypt licensed under BSD 2-Clause, Copyright 2009 Colin Percival
