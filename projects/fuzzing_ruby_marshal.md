
# Fuzzing ruby marshalling function.

This is my writeup of fuzzing ruby internals. Next up is ruby serialization/deserialization. This writeup is inspired by this: https://medium.com/fuzzstation/breaking-rubys-unmarshal-with-afl-fuzz-6b5f72b581d5 which describes a method to fuzz rubys unmarshal method with afl-fuzz .

## Attack plan

The original blog post used a simple "./ruby unmarshal.rb"  to fuzz the unmarshalling function. I think that this is very inefficient because on every cycle the fuzzer must setup the ruby environment and then close the ruby virtual machine on each cycle. This is very slow. Instead I want to use the rubys C language api functions to accomplish this task from C. This has the added bonus that we can use the __AFL_LOOP macro to get persistent fuzzing which is a lot faster than trying to setup everything over and over again.



After a bit of tinkering, I came up with this:

{% raw %}
```


#include <ruby.h>
#include "ruby/re.h"

#include <stdlib.h>




#define MAX_INPUT_SIZE 1000





VALUE handle_error(VALUE obj1) {

	return 0;
}




VALUE dangerous_func(VALUE x)
{
	/* code that could raise an exception */
	int result;
	result = rb_marshal_load(x);
	rb_gc_unregister_address(result);
	//free(result);
	return 0;

	// rb_gc_unregister_address
	//return result;
}




int main(int argc, char** argv) {
	
	VALUE x;
	VALUE result;

	int state = 0;
	
	char string[MAX_INPUT_SIZE];
	ruby_setup();
	//ruby_init();

	//ruby_init_loadpath();



	while (__AFL_LOOP(1000)) {

		state = 0;

		memset(string, 0, MAX_INPUT_SIZE);

		//fgets(string, MAX_INPUT_SIZE, stdin);

		read(0, string, MAX_INPUT_SIZE);



		if (string[MAX_INPUT_SIZE-2]) {
			return 0;
		}

		x = rb_str_new_cstr(string);

		printf("Calling the function: \n");
		result = rb_protect(dangerous_func, x, &state);

		printf("Result: %d\n", state);

	}
	

	//printf("%d\n", state);



	ruby_cleanup(0);


	return 0;



}



```
{% endraw %}


This initially works, but after a while the fuzzer gets an out of memory error. This is because the code does not free the allocated object which gets alloc'ed by rb_marshal_load . The function rb_gc_unregister_address is used to mark an object as unused for the ruby virtual machine such that the object is no-longer used and that the object should be freed, but this does not seem to work. I still get an OOM error after a couple of minutes of fuzzing .


## Reading some documentation and source code.

Looking through the documentation there does not appear to be a singular example which uses rb_marshal_load in the code.

Looking through the source code gives atleast some clues as to how we may be able to free the allocated object. rb_marshal_load internally calls rb_marshal_load_with_proc .


in rb_marshal_load_with_proc:

{% raw %}
```

    if (NIL_P(v))
        arg->buf = xmalloc(BUFSIZ);
    else
        arg->buf = 0;

```
{% endraw %}

also

{% raw %}
```

    v = r_object(arg);
    clear_load_arg(arg);
    RB_GC_GUARD(wrapper);

    return v;
```
{% endraw %}

also also:


{% raw %}
```

static VALUE
r_object(struct load_arg *arg)
{
    return r_object0(arg, false, 0, Qnil);
}
```
{% endraw %}


also also also:


{% raw %}
```

static VALUE
r_object0(struct load_arg *arg, bool partial, int *ivp, VALUE extmod)
{
    int type = r_byte(arg);
    return r_object_for(arg, partial, ivp, extmod, type);
}

```
{% endraw %}



in r_object_for :

{% raw %}
```
      case TYPE_STRING:
        v = r_entry(r_string(arg), arg);
        v = r_leave(v, arg, partial);
        break;

```
{% endraw %}


in r_leave:



{% raw %}
```


static VALUE
r_leave(VALUE v, struct load_arg *arg, bool partial)
{
    v = r_fixup_compat(v, arg);
    if (!partial) {
        st_data_t data;
        st_data_t key = (st_data_t)v;
        st_delete(arg->partial_objects, &key, &data);
        if (arg->freeze) {
            if (RB_TYPE_P(v, T_MODULE) || RB_TYPE_P(v, T_CLASS)) {
                // noop
            }
            else if (RB_TYPE_P(v, T_STRING)) {
                v = rb_str_to_interned_str(v);
            }
            else {
                OBJ_FREEZE(v);
            }
        }
        v = r_post_proc(v, arg);
    }
    return v;
}


```
{% endraw %}

and:


{% raw %}
```

static VALUE
r_fixup_compat(VALUE v, struct load_arg *arg)
{
    st_data_t data;
    st_data_t key = (st_data_t)v;
    if (arg->compat_tbl && st_delete(arg->compat_tbl, &key, &data)) {
        VALUE real_obj = (VALUE)data;
        rb_alloc_func_t allocator = rb_get_alloc_func(CLASS_OF(real_obj));
        if (st_lookup(compat_allocator_tbl, (st_data_t)allocator, &data)) {
            marshal_compat_t *compat = (marshal_compat_t*)data;
            compat->loader(real_obj, v);
        }
        v = real_obj;
    }
    return v;
}


```
{% endraw %}



After looking at the code I still have no idea of how I can free the alloc'ed object. Anyway, I am going to get rid of that problem later.

Now here are all of the possible types for the object:

{% raw %}
```
static void
w_object(VALUE obj, struct dump_arg *arg, int limit)
{
    struct dump_call_arg c_arg;
    VALUE ivobj = Qundef;
    st_data_t num;
    st_index_t hasiv = 0;
    VALUE encname = Qnil;

    if (limit == 0) {
        rb_raise(rb_eArgError, "exceed depth limit");
    }

    if (NIL_P(obj)) {
        w_byte(TYPE_NIL, arg);
    }
    else if (obj == Qtrue) {
        w_byte(TYPE_TRUE, arg);
    }
    else if (obj == Qfalse) {
        w_byte(TYPE_FALSE, arg);
    }
    else if (FIXNUM_P(obj)) {
#if SIZEOF_LONG <= 4
        w_byte(TYPE_FIXNUM, arg);
        w_long(FIX2INT(obj), arg);
#else
        if (RSHIFT((long)obj, 31) == 0 || RSHIFT((long)obj, 31) == -1) {
            w_byte(TYPE_FIXNUM, arg);
            w_long(FIX2LONG(obj), arg);
        }
        else {
            w_bigfixnum(obj, arg);
        }
#endif
    }
    else if (SYMBOL_P(obj)) {
        w_symbol(obj, arg);
    }
    else {
        if (st_lookup(arg->data, obj, &num)) {
            w_byte(TYPE_LINK, arg);
            w_long((long)num, arg);
            return;
        }

        if (limit > 0) limit--;
        c_arg.limit = limit;
        c_arg.arg = arg;
        c_arg.obj = obj;

        if (FLONUM_P(obj)) {
            w_remember(obj, arg);
            w_byte(TYPE_FLOAT, arg);
            w_float(RFLOAT_VALUE(obj), arg);
            return;
        }

        VALUE v;

        if (!RBASIC_CLASS(obj)) {
            rb_raise(rb_eTypeError, "can't dump internal %s",
                     rb_builtin_type_name(BUILTIN_TYPE(obj)));
        }

        if (rb_obj_respond_to(obj, s_mdump, TRUE)) {
            w_remember(obj, arg);

            v = dump_funcall(arg, obj, s_mdump, 0, 0);
            w_class(TYPE_USRMARSHAL, obj, arg, FALSE);
            w_object(v, arg, limit);
            return;
        }
        if (rb_obj_respond_to(obj, s_dump, TRUE)) {
            VALUE ivobj2 = Qundef;
            st_index_t hasiv2;
            VALUE encname2;

            v = INT2NUM(limit);
            v = dump_funcall(arg, obj, s_dump, 1, &v);
            if (!RB_TYPE_P(v, T_STRING)) {
                rb_raise(rb_eTypeError, "_dump() must return string");
            }
            hasiv = has_ivars(obj, (encname = encoding_name(obj, arg)), &ivobj);
            hasiv2 = has_ivars(v, (encname2 = encoding_name(v, arg)), &ivobj2);
            if (hasiv2) {
                hasiv = hasiv2;
                ivobj = ivobj2;
                encname = encname2;
            }
            if (hasiv) w_byte(TYPE_IVAR, arg);
            w_class(TYPE_USERDEF, obj, arg, FALSE);
            w_bytes(RSTRING_PTR(v), RSTRING_LEN(v), arg);
            if (hasiv) {
                w_ivar(hasiv, ivobj, encname, &c_arg);
            }
            w_remember(obj, arg);
            return;
        }

        w_remember(obj, arg);

        hasiv = has_ivars(obj, (encname = encoding_name(obj, arg)), &ivobj);
        {
            st_data_t compat_data;
            rb_alloc_func_t allocator = rb_get_alloc_func(RBASIC(obj)->klass);
            if (st_lookup(compat_allocator_tbl,
                          (st_data_t)allocator,
                          &compat_data)) {
                marshal_compat_t *compat = (marshal_compat_t*)compat_data;
                VALUE real_obj = obj;
                obj = compat->dumper(real_obj);
                if (!arg->compat_tbl) {
                    arg->compat_tbl = rb_init_identtable();
                }
                st_insert(arg->compat_tbl, (st_data_t)obj, (st_data_t)real_obj);
                if (obj != real_obj && UNDEF_P(ivobj)) hasiv = 0;
            }
        }
        if (hasiv) w_byte(TYPE_IVAR, arg);

        switch (BUILTIN_TYPE(obj)) {
          case T_CLASS:
            if (FL_TEST(obj, FL_SINGLETON)) {
                rb_raise(rb_eTypeError, "singleton class can't be dumped");
            }
            w_byte(TYPE_CLASS, arg);
            {
                VALUE path = class2path(obj);
                w_bytes(RSTRING_PTR(path), RSTRING_LEN(path), arg);
                RB_GC_GUARD(path);
            }
            break;

          case T_MODULE:
            w_byte(TYPE_MODULE, arg);
            {
                VALUE path = class2path(obj);
                w_bytes(RSTRING_PTR(path), RSTRING_LEN(path), arg);
                RB_GC_GUARD(path);
            }
            break;

          case T_FLOAT:
            w_byte(TYPE_FLOAT, arg);
            w_float(RFLOAT_VALUE(obj), arg);
            break;

          case T_BIGNUM:
            w_byte(TYPE_BIGNUM, arg);
            {
                char sign = BIGNUM_SIGN(obj) ? '+' : '-';
                size_t len = BIGNUM_LEN(obj);
                size_t slen;
                size_t j;
                BDIGIT *d = BIGNUM_DIGITS(obj);

                slen = SHORTLEN(len);
                if (LONG_MAX < slen) {
                    rb_raise(rb_eTypeError, "too big Bignum can't be dumped");
                }

                w_byte(sign, arg);
                w_long((long)slen, arg);
                for (j = 0; j < len; j++) {
#if SIZEOF_BDIGIT > SIZEOF_SHORT
                    BDIGIT num = *d;
                    int i;

                    for (i=0; i<SIZEOF_BDIGIT; i+=SIZEOF_SHORT) {
                        w_short(num & SHORTMASK, arg);
                        num = SHORTDN(num);
                        if (j == len - 1 && num == 0) break;
                    }
#else
                    w_short(*d, arg);
#endif
                    d++;
                }
            }
            break;

          case T_STRING:
            w_uclass(obj, rb_cString, arg);
            w_byte(TYPE_STRING, arg);
            w_bytes(RSTRING_PTR(obj), RSTRING_LEN(obj), arg);
            break;

          case T_REGEXP:
            w_uclass(obj, rb_cRegexp, arg);
            w_byte(TYPE_REGEXP, arg);
            {
                int opts = rb_reg_options(obj);
                w_bytes(RREGEXP_SRC_PTR(obj), RREGEXP_SRC_LEN(obj), arg);
                w_byte((char)opts, arg);
            }
            break;

          case T_ARRAY:
            w_uclass(obj, rb_cArray, arg);
            w_byte(TYPE_ARRAY, arg);
            {
                long i, len = RARRAY_LEN(obj);

                w_long(len, arg);
                for (i=0; i<RARRAY_LEN(obj); i++) {
                    w_object(RARRAY_AREF(obj, i), arg, limit);
                    if (len != RARRAY_LEN(obj)) {
                        rb_raise(rb_eRuntimeError, "array modified during dump");
                    }
                }
            }
            break;

          case T_HASH:
            w_uclass(obj, rb_cHash, arg);
            if (rb_hash_compare_by_id_p(obj)) {
                w_byte(TYPE_UCLASS, arg);
                w_symbol(rb_sym_intern_ascii_cstr("Hash"), arg);
            }
            if (NIL_P(RHASH_IFNONE(obj))) {
                w_byte(TYPE_HASH, arg);
            }
            else if (FL_TEST(obj, RHASH_PROC_DEFAULT)) {
                rb_raise(rb_eTypeError, "can't dump hash with default proc");
            }
            else {
                w_byte(TYPE_HASH_DEF, arg);
            }
            w_long(rb_hash_size_num(obj), arg);
            rb_hash_foreach(obj, hash_each, (st_data_t)&c_arg);
            if (!NIL_P(RHASH_IFNONE(obj))) {
                w_object(RHASH_IFNONE(obj), arg, limit);
            }
            break;

          case T_STRUCT:
            w_class(TYPE_STRUCT, obj, arg, TRUE);
            {
                long len = RSTRUCT_LEN(obj);
                VALUE mem;
                long i;

                w_long(len, arg);
                mem = rb_struct_members(obj);
                for (i=0; i<len; i++) {
                    w_symbol(RARRAY_AREF(mem, i), arg);
                    w_object(RSTRUCT_GET(obj, i), arg, limit);
                }
            }
            break;

          case T_OBJECT:
            w_class(TYPE_OBJECT, obj, arg, TRUE);
            w_objivar(obj, &c_arg);
            break;

          case T_DATA:
            {
                VALUE v;

                if (!rb_obj_respond_to(obj, s_dump_data, TRUE)) {
                    rb_raise(rb_eTypeError,
                             "no _dump_data is defined for class %"PRIsVALUE,
                             rb_obj_class(obj));
                }
                v = dump_funcall(arg, obj, s_dump_data, 0, 0);
                w_class(TYPE_DATA, obj, arg, TRUE);
                w_object(v, arg, limit);
            }
            break;

          default:
            rb_raise(rb_eTypeError, "can't dump %"PRIsVALUE,
                     rb_obj_class(obj));
            break;
        }
        RB_GC_GUARD(obj);
    }
    if (hasiv) {
        w_ivar(hasiv, ivobj, encname, &c_arg);
    }
}

```
{% endraw %}



the only interesting ones are basically strings, regexes, floats, integers, lists and hashes basically. I made a few marshal dumps of those objects and then added them to my corpus and then started fuzzing. Lets see if we find crashes.















