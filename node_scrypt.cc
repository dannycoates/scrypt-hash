#include <string.h>
#include <node.h>
#include "nan.h"

extern "C" {
	#include "crypto_scrypt.h"
}

#define ASSERT_IS_BUFFER(val) \
	if (!node::Buffer::HasInstance(val)) { \
		return Nan::ThrowError("not a buffer"); \
	}

#define ASSERT_IS_NUMBER(val) \
	if (!val->IsNumber()) { \
		return Nan::ThrowError("not a number"); \
	}

using namespace v8;

class ScryptWorker : public Nan::AsyncWorker {
public:
	ScryptWorker(
		Nan::Callback *callback,
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
	Nan::AsyncWorker(callback),
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
			SetErrorMessage("Scrypt Error");
		}
		memset(pass, 0, pass_len);
		memset(salt, 0, salt_len);
	};

	void HandleOKCallback () {
		Nan::HandleScope scope;

		Local<Value> argv[] = {
			Nan::Undefined(),
			Nan::CopyBuffer(buf, buf_len).ToLocalChecked()
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
	Nan::HandleScope scope;

	char* pass = NULL;
	ssize_t pass_len = -1;
	char* salt = NULL;
	ssize_t salt_len = -1;
	uint64_t N = 0;
	uint32_t r = 0;
	uint32_t p = 0;
	uint8_t buf_len = 0;
	Nan::Callback *callback = 0;

	if (info.Length() != 7) {
		return Nan::ThrowError("Bad parameters");
	}
	ASSERT_IS_BUFFER(info[0]);
	ASSERT_IS_BUFFER(info[1]);
	ASSERT_IS_NUMBER(info[2]);
	ASSERT_IS_NUMBER(info[3]);
	ASSERT_IS_NUMBER(info[4]);
	ASSERT_IS_NUMBER(info[5]);
	if (!info[6]->IsFunction()) {
		return Nan::ThrowError("callback not a function");
	}

#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 10
	Local<Object> data_buf = info[0]->ToObject();
	Local<Object> salt_buf = info[1]->ToObject();
#else
	Local<Value> data_buf = info[0];
	Local<Value> salt_buf = info[1];
#endif

	pass_len = node::Buffer::Length(data_buf);
	if (pass_len < 0) {
		return Nan::ThrowError("Bad data");
	}

	salt_len = node::Buffer::Length(salt_buf);
	if (salt_len < 0) {
		return Nan::ThrowError("Bad salt");
	}

	N = info[2]->Uint32Value();
	r = info[3]->Uint32Value();
	p = info[4]->Uint32Value();
	buf_len = info[5]->Uint32Value();
	callback = new Nan::Callback(info[6].As<Function>());
	pass = new char[pass_len];
	memcpy(pass, node::Buffer::Data(data_buf), pass_len);

	salt = new char[salt_len];
	memcpy(salt, node::Buffer::Data(salt_buf), salt_len);

	Nan::AsyncQueueWorker(
		new ScryptWorker(callback, pass, pass_len, salt, salt_len, N, r, p, buf_len)
	);
}


NAN_MODULE_INIT(init) {
	Nan::Set(target, Nan::New<String>("scrypt").ToLocalChecked(),
		Nan::GetFunction(Nan::New<FunctionTemplate>(Scrypt)).ToLocalChecked());
}

NODE_MODULE(scrypt, init);
