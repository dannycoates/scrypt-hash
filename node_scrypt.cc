#include <string.h>
#include <node.h>
#include "nan.h"

extern "C" {
	#include "crypto_scrypt.h"
}

#define ASSERT_IS_BUFFER(val) \
	if (!node::Buffer::HasInstance(val)) { \
		return NanThrowError("not a buffer"); \
	}

#define ASSERT_IS_NUMBER(val) \
	if (!val->IsNumber()) { \
		return NanThrowError("not a number"); \
	}

using namespace v8;

class ScryptWorker : public NanAsyncWorker {
public:
	ScryptWorker(
		NanCallback *callback,
		char* pass,
		size_t pass_len,
		char* salt,
		size_t salt_len,
		uint64_t N,
		uint32_t r,
		uint32_t p,
		size_t buf_len
		)
	:
	NanAsyncWorker(callback),
	pass(pass),
	pass_len(pass_len),
	salt(salt),
	salt_len(salt_len),
	N(N),
	r(r),
	p(p),
	buf_len(buf_len) {}

	~ScryptWorker() {
		delete[] pass;
		delete[] salt;
		delete[] buf;
	}

	void Execute () {
		buf = new char[buf_len];
		if (
			crypto_scrypt(
				(const uint8_t*)pass,
				pass_len,
				(const uint8_t*)salt,
				salt_len,
				N,
				r,
				p,
				(uint8_t*)buf,
				buf_len)
			) {
			errmsg = "Scrypt Error";
		}
		memset(pass, 0, pass_len);
		memset(salt, 0, salt_len);
	};

	void HandleOKCallback () {
		NanScope();
		Local<Value> argv[] = {
			NanNewLocal<Value>(Undefined()),
			NanNewBufferHandle(buf, buf_len)
		};
		callback->Call(2, argv);
	};

private:
	char* pass;
	size_t pass_len;
	char* salt;
	size_t salt_len;
	uint64_t N;
	uint32_t r;
	uint32_t p;
	char* buf;
	size_t buf_len;
};

NAN_METHOD(Scrypt) {
	NanScope();

	char* pass = NULL;
	ssize_t pass_len = -1;
	ssize_t pass_written = -1;
	char* salt = NULL;
	ssize_t salt_len = -1;
	ssize_t salt_written = -1;
	uint64_t N = 0;
	uint32_t r = 0;
	uint32_t p = 0;
	uint8_t buf_len = 0;
	NanCallback *callback = 0;

	if (args.Length() != 7) {
		return NanThrowError("Bad parameters");
	}
	ASSERT_IS_BUFFER(args[0]);
	ASSERT_IS_BUFFER(args[1]);
	ASSERT_IS_NUMBER(args[2]);
	ASSERT_IS_NUMBER(args[3]);
	ASSERT_IS_NUMBER(args[4]);
	ASSERT_IS_NUMBER(args[5]);
	if (!args[6]->IsFunction()) {
		return NanThrowError("callback not a function");
	}

#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 10
	Local<Object> data_buf = args[0]->ToObject();
	Local<Object> salt_buf = args[1]->ToObject();
#else
	Local<Value> data_buf = args[0];
	Local<Value> salt_buf = args[1];
#endif

	pass_len = node::Buffer::Length(data_buf);
	if (pass_len < 0) {
		return NanThrowError("Bad data");
	}

	salt_len = node::Buffer::Length(salt_buf);
	if (salt_len < 0) {
		return NanThrowError("Bad salt");
	}

	N = args[2]->Uint32Value();
	r = args[3]->Uint32Value();
	p = args[4]->Uint32Value();
	buf_len = args[5]->Uint32Value();
	callback = new NanCallback(args[6].As<Function>());
	pass = new char[pass_len];
	pass_written = node::DecodeWrite(pass, pass_len, args[0], node::BINARY);
	assert(pass_len == pass_written);
	salt = new char[salt_len];
	salt_written = node::DecodeWrite(salt, salt_len, args[1], node::BINARY);
	assert(salt_len == salt_written);

	NanAsyncQueueWorker(
		new ScryptWorker(callback, pass, pass_len, salt, salt_len, N, r, p, buf_len)
	);
	NanReturnUndefined();
}

void init(Handle<Object> exports) {
	exports->Set(NanSymbol("scrypt"),
		FunctionTemplate::New(Scrypt)->GetFunction());
}

NODE_MODULE(scrypt, init);
