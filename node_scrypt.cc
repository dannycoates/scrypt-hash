#include <string.h>
#include <node.h>
#include <node_internals.h>
#include <node_buffer.h>
#include <v8.h>

extern "C" {
	#include "crypto_scrypt.h"
}

#define ASSERT_IS_BUFFER(val) \
	if (!Buffer::HasInstance(val)) { \
		return ThrowException(Exception::TypeError(String::New("Not a buffer"))); \
	}

#define ASSERT_IS_NUMBER(val) \
	if (!val->IsNumber()) { \
		type_error = "not a number"; \
		goto err; \
	}

using namespace v8;
using namespace node;

struct scrypt_req {
	uv_work_t work_req;
	int err;
	char* pass;
	size_t pass_len;
	char* salt;
	size_t salt_len;
	uint64_t N;
	uint32_t r;
	uint32_t p;
	char* buf;
	size_t buf_len;
	Persistent<Object> obj;
};

void EIO_Scrypt(uv_work_t* work_req) {
	scrypt_req* req = container_of(work_req, scrypt_req, work_req);
	req->err = crypto_scrypt(
		(const uint8_t*)req->pass,
		req->pass_len,
		(const uint8_t*)req->salt,
		req->salt_len,
		req->N,
		req->r,
		req->p,
		(uint8_t*)req->buf,
		req->buf_len);
	memset(req->pass, 0, req->pass_len);
	memset(req->salt, 0, req->salt_len);
}

void EIO_ScryptAfter(uv_work_t* work_req, int status) {
	assert(status == 0);
	scrypt_req* req = container_of(work_req, scrypt_req, work_req);
	HandleScope scope;
	Local<Value> argv[2];
	Persistent<Object> obj = req->obj;
	if (req->err) {
		argv[0] = Exception::Error(String::New("Scrypt error"));
		argv[1] = Local<Value>::New(Undefined());
	}
	else {
		argv[0] = Local<Value>::New(Undefined());
		argv[1] = Encode(req->buf, req->buf_len, BUFFER);
	}
	MakeCallback(obj, "ondone", ARRAY_SIZE(argv), argv);
	obj.Dispose();
	delete[] req->pass;
	delete[] req->salt;
	delete[] req->buf;
	delete req;
}

Handle<Value> Scrypt(const Arguments& args) {
	HandleScope scope;

	const char* type_error = NULL;
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
	scrypt_req* req = NULL;

	if (args.Length() != 7) {
		type_error = "Bad parameters";
		goto err;
	}

	ASSERT_IS_BUFFER(args[0]);
	pass_len = Buffer::Length(args[0]);
	if (pass_len < 0) {
		type_error = "Bad data";
		goto err;
	}
	pass = new char[pass_len];
	pass_written = DecodeWrite(pass, pass_len, args[0], BINARY);
	assert(pass_len == pass_written);

	ASSERT_IS_BUFFER(args[1]);
	salt_len = Buffer::Length(args[1]);
	if (salt_len < 0) {
		type_error = "Bad salt";
		goto err;
	}
	salt = new char[salt_len];
	salt_written = DecodeWrite(salt, salt_len, args[1], BINARY);
	assert(salt_len == salt_written);

	ASSERT_IS_NUMBER(args[2]);
	N = args[2]->Int32Value();

	ASSERT_IS_NUMBER(args[3]);
	r = args[3]->Int32Value();

	ASSERT_IS_NUMBER(args[4]);
	p = args[4]->Int32Value();

	ASSERT_IS_NUMBER(args[5]);
	buf_len = args[5]->Int32Value();

	if (!args[6]->IsFunction()) {
		type_error = "callback not a function";
		goto err;
	}

	req = new scrypt_req;
	req->err = 0;
	req->pass = pass;
	req->pass_len = pass_len;
	req->salt = salt;
	req->salt_len = salt_len;
	req->N = N;
	req->r = r;
	req->p = p;
	req->buf = new char[buf_len];
	req->buf_len = buf_len;
	req->obj = Persistent<Object>::New(Object::New());
	req->obj->Set(String::New("ondone"), args[6]);
	uv_queue_work(uv_default_loop(), &req->work_req, EIO_Scrypt, EIO_ScryptAfter);
	return Undefined();

err:
	delete[] salt;
	delete[] pass;
	return ThrowException(Exception::TypeError(String::New(type_error)));
}

void init(Handle<Object> target) {
	NODE_SET_METHOD(target, "scrypt", Scrypt);
}

NODE_MODULE(scrypt, init);
