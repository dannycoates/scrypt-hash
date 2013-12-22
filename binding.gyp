{
	'targets': [
		{
			'target_name': 'scrypt',
			'sources': [
				'sha256.c',
				'crypto_scrypt-sse.c',
				'node_scrypt.cc'
			],
			'defines': [
				'HAVE_CONFIG_H'
			]
		}
	]
}
