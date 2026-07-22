package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
static const cliproxy_host_api* stored_host;
static void store_host_api(const cliproxy_host_api* host) { stored_host = host; }
static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) return 1;
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}
static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) stored_host->free_buffer(ptr, len);
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type rpcEnvelope struct {
	OK     bool             `json:"ok"`
	Result json.RawMessage  `json:"result,omitempty"`
	Error  *pluginabi.Error `json:"error,omitempty"`
}

type nativeHost struct{}

var productionRuntime = newAgentIdentityRuntime(nativeHost{})

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writePluginResponse(response, errorEnvelope("invalid method"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	result, err := handlePluginMethod(productionRuntime, C.GoString(method), requestBytes)
	if err != nil {
		writePluginResponse(response, errorEnvelope(err.Error()))
		return 1
	}
	writePluginResponse(response, successEnvelope(result))
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func (nativeHost) getAuth(callbackID, authIndex string) (pluginapi.HostAuthGetResponse, error) {
	var response pluginapi.HostAuthGetResponse
	err := callHost(pluginabi.MethodHostAuthGet, map[string]any{"host_callback_id": callbackID, "auth_index": authIndex}, &response)
	return response, err
}

func (nativeHost) saveAuth(callbackID, name string, raw json.RawMessage) error {
	var response pluginapi.HostAuthSaveResponse
	return callHost(pluginabi.MethodHostAuthSave, map[string]any{"host_callback_id": callbackID, "name": name, "json": raw}, &response)
}

func (nativeHost) doHTTP(callbackID string, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	var response pluginapi.HTTPResponse
	err := callHost(pluginabi.MethodHostHTTPDo, map[string]any{
		"host_callback_id": callbackID,
		"method":           req.Method,
		"url":              req.URL,
		"headers":          req.Headers,
		"body":             req.Body,
	}, &response)
	return response, err
}

func callHost(method string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return errors.New("failed to encode host callback")
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var requestPtr *C.uint8_t
	if len(raw) > 0 {
		ptr := C.CBytes(raw)
		if ptr == nil {
			return errors.New("failed to allocate host callback")
		}
		defer C.free(ptr)
		requestPtr = (*C.uint8_t)(ptr)
	}
	var response C.cliproxy_buffer
	code := C.call_host_api(cMethod, requestPtr, C.size_t(len(raw)), &response)
	var responseBytes []byte
	if response.ptr != nil && response.len > 0 {
		responseBytes = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(response.ptr, response.len)
	}
	if code != 0 || len(responseBytes) == 0 {
		return errors.New("host callback failed")
	}
	var envelope rpcEnvelope
	if err = json.Unmarshal(responseBytes, &envelope); err != nil || !envelope.OK {
		return errors.New("host callback failed")
	}
	if err = json.Unmarshal(envelope.Result, out); err != nil {
		return errors.New("host callback response is invalid")
	}
	return nil
}

func successEnvelope(result any) []byte {
	raw, err := json.Marshal(result)
	if err != nil {
		return errorEnvelope("plugin response serialization failed")
	}
	envelope, _ := json.Marshal(rpcEnvelope{OK: true, Result: raw})
	return envelope
}

func errorEnvelope(message string) []byte {
	raw, _ := json.Marshal(rpcEnvelope{OK: false, Error: &pluginabi.Error{Code: "plugin_error", Message: message}})
	return raw
}

func writePluginResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
