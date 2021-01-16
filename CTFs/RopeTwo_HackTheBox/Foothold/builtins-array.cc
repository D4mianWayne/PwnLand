 return GenericArrayFill(isolate, receiver, value, start_index, end_index);
}

BUILTIN(ArrayGetLastElement)
{
	Handle<JSReceiver> receiver;
	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
	Handle<JSArray> array = Handle<JSArray>::cast(receiver);
	uint32_t len = static_cast<uint32_t>(array->length().Number());
	FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
	return *(isolate->factory()->NewNumber(elements.get_scalar(len)));
}

BUILTIN(ArraySetLastElement)
{
	Handle<JSReceiver> receiver;
	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
	int arg_count = args.length();
	if (arg_count != 2) // first value is always this
	{
		return ReadOnlyRoots(isolate).undefined_value();
	}
	Handle<JSArray> array = Handle<JSArray>::cast(receiver);
	uint32_t len = static_cast<uint32_t>(array->length().Number());
	Handle<Object> value;
	ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value, Object::ToNumber(isolate, args.atOrUndefined(isolate,1)));
	FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
	elements.set(len,value->Number());
	return ReadOnlyRoots(isolate).undefined_value();
}

namespace {
V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
                                              BuiltinArguments* args) {

