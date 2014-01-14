{
	'targets': [
		{
			'target_name': 'scrypt',
			'sources': [
				'crypto_scrypt-sse.c',
				'node_scrypt.cc'
			],
			'defines': [
				'HAVE_CONFIG_H'
			],
			'include_dirs' : ["<!(node -e \"require('nan')\")"],
			# borrowed from bignum: https://github.com/justmoon/node-bignum/blob/master/binding.gyp
			'conditions':
			[
				# For Windows, require either a 32-bit or 64-bit
				# separately-compiled OpenSSL library.
				# Currently set up to use with the following OpenSSL distro:
				#
				# http://slproweb.com/products/Win32OpenSSL.html
				[
					'OS=="win"',
					{
						'conditions':
						[
							[
								'target_arch=="x64"',
								{
									'variables': {
										'openssl_root%': 'C:/OpenSSL-Win64'
									},
								}, {
								 'variables': {
									 'openssl_root%': 'C:/OpenSSL-Win32'
									}
								}
							]
						],
						'libraries': [
							'-l<(openssl_root)/lib/libeay32.lib',
						],
						'include_dirs': [
							'<(openssl_root)/include',
						],
					},


					# Otherwise, if not Windows, link against the exposed OpenSSL
					# in Node.
					{
						'conditions':
						[
							[
								'target_arch=="ia32"',
								{
									'variables': {
										'openssl_config_path': '<(nodedir)/deps/openssl/config/piii'
									}
								}
							],
							[
								'target_arch=="x64"', {
									'variables': {
										'openssl_config_path': '<(nodedir)/deps/openssl/config/k8'
									},
								}
							],
							[
								'target_arch=="arm"', {
									'variables': {
										'openssl_config_path': '<(nodedir)/deps/openssl/config/arm'
									}
								}
							],
						],
						'include_dirs': [
							"<(nodedir)/deps/openssl/openssl/include",
							"<(openssl_config_path)"
						]
					}
				]
			]
		}
	]
}
