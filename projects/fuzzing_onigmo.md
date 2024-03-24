
# Fuzzing the onigmo ruby wrapper.

Ok, so I was searching on Shopifys github account and came across this: https://github.com/Shopify/onigmo/tree/main which was uploaded just five days ago. This means that the code probably has plenty of bugs in it.

I already fuzzed html_tokenizer which was another Shopifys ruby extension. I didn't find any bugs in it, but it gave me plenty of experience and now I know how to fuzz other ruby extensions too.

## Writing a wrapper.

Now my initial attempt at writing a fuzzing wrapper was this:

```
static VALUE thing(VALUE self) {
    printf("Called thing");
    return Qnil;
}

int main(int argc, char** argv) {
    ruby_init();
    VALUE cFoo = rb_define_class("Foo", rb_cObject);


    rb_define_method(cFoo, "parse", parse, 1);
    rb_define_method(cFoo, "compile", compile, 1);
    rb_define_method(cFoo, "fuck", thing, 0);




    VALUE rb_cOnigmo = rb_define_module("Onigmo");
    rb_define_singleton_method(rb_cOnigmo, "parse", parse, 1);
    rb_define_singleton_method(rb_cOnigmo, "compile", compile, 1);

    //rb_define_method(rb_cOnigmo, "fuck", thing, 0);

    VALUE x;
    //x = rb_str_new_cstr("<div>"); // Example html string.

    x = rb_str_new_cstr("a"); // Simple regex

    VALUE obj = rb_class_new_instance(0, NULL, cFoo);
    // rb_funcall(obj, rb_intern("parse"), 1, x);

    // VALUE obj2 = rb_class_new_instance(0, NULL, rb_cOnigmo);

    // obj

    rb_funcall(obj, rb_intern("fuck"), 0);


    rb_funcall(obj, rb_intern("parse"), 1, x);




    //rb_funcall(obj2, rb_intern("fuck"), 0);

    //rb_funcall(obj2, rb_intern("parse"), 1, x);
    
    //return 0;
    return ruby_cleanup(0);
}




```

(just append that to the onigmo.c file in the source code)

but it didn't work. This is because it crashed on this line in build_node: `return rb_class_new_instance(2, argv, rb_cOnigmoCallNode);`

This is because there is the initialization function which looks like this: 

```

void
Init_onigmo(void) {
    VALUE rb_cOnigmo = rb_define_module("Onigmo");
    rb_define_singleton_method(rb_cOnigmo, "parse", parse, 1);
    rb_define_singleton_method(rb_cOnigmo, "compile", compile, 1);

    rb_cOnigmoNode = rb_define_class_under(rb_cOnigmo, "Node", rb_cObject);
    rb_cOnigmoAlternationNode = rb_define_class_under(rb_cOnigmo, "AlternationNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorBufferBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorBufferBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorBufferEndNode = rb_define_class_under(rb_cOnigmo, "AnchorBufferEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorKeepNode = rb_define_class_under(rb_cOnigmo, "AnchorKeepNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorLineBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorLineBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorLineEndNode = rb_define_class_under(rb_cOnigmo, "AnchorLineEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorPositionBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorPositionBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorSemiEndNode = rb_define_class_under(rb_cOnigmo, "AnchorSemiEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorWordBoundaryNode = rb_define_class_under(rb_cOnigmo, "AnchorWordBoundaryNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorWordBoundaryInvertNode = rb_define_class_under(rb_cOnigmo, "AnchorWordBoundaryInvertNode", rb_cOnigmoNode);
    rb_cOnigmoAnyNode = rb_define_class_under(rb_cOnigmo, "AnyNode", rb_cOnigmoNode);
    rb_cOnigmoBackrefNode = rb_define_class_under(rb_cOnigmo, "BackrefNode", rb_cOnigmoNode);
    rb_cOnigmoCallNode = rb_define_class_under(rb_cOnigmo, "CallNode", rb_cOnigmoNode);
    rb_cOnigmoCClassNode = rb_define_class_under(rb_cOnigmo, "CClassNode", rb_cOnigmoNode);
    rb_cOnigmoCClassInvertNode = rb_define_class_under(rb_cOnigmo, "CClassInvertNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseAbsentNode = rb_define_class_under(rb_cOnigmo, "EncloseAbsentNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseConditionNode = rb_define_class_under(rb_cOnigmo, "EncloseConditionNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseMemoryNode = rb_define_class_under(rb_cOnigmo, "EncloseMemoryNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseOptionsNode = rb_define_class_under(rb_cOnigmo, "EncloseOptionsNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseStopBacktrackNode = rb_define_class_under(rb_cOnigmo, "EncloseStopBacktrackNode", rb_cOnigmoNode);
    rb_cOnigmoListNode = rb_define_class_under(rb_cOnigmo, "ListNode", rb_cOnigmoNode);
    rb_cOnigmoLookAheadNode = rb_define_class_under(rb_cOnigmo, "LookAheadNode", rb_cOnigmoNode);
    rb_cOnigmoLookAheadInvertNode = rb_define_class_under(rb_cOnigmo, "LookAheadInvertNode", rb_cOnigmoNode);
    rb_cOnigmoLookBehindNode = rb_define_class_under(rb_cOnigmo, "LookBehindNode", rb_cOnigmoNode);
    rb_cOnigmoLookBehindInvertNode = rb_define_class_under(rb_cOnigmo, "LookBehindInvertNode", rb_cOnigmoNode);
    rb_cOnigmoQuantifierNode = rb_define_class_under(rb_cOnigmo, "QuantifierNode", rb_cOnigmoNode);
    rb_cOnigmoStringNode = rb_define_class_under(rb_cOnigmo, "StringNode", rb_cOnigmoNode);
    rb_cOnigmoWordNode = rb_define_class_under(rb_cOnigmo, "WordNode", rb_cOnigmoNode);
    rb_cOnigmoWordInvertNode = rb_define_class_under(rb_cOnigmo, "WordInvertNode", rb_cOnigmoNode);
}

```

so I think that I need to copy all of that to my fuzzing harness and then create an instance of the rb_cOnigmo object and then call parse on that function... let's see.

Here is my current wrapper:

```

static VALUE thing(VALUE self) {
    printf("Called thing");
    return Qnil;
}

int main(int argc, char** argv) {
    ruby_init();
    VALUE cFoo = rb_define_class("Foo", rb_cObject);


    rb_define_method(cFoo, "parse", parse, 1);
    rb_define_method(cFoo, "compile", compile, 1);
    rb_define_method(cFoo, "fuck", thing, 0);




    //VALUE rb_cOnigmo = rb_define_module("Onigmo");
    //rb_define_singleton_method(rb_cOnigmo, "parse", parse, 1);
    //rb_define_singleton_method(rb_cOnigmo, "compile", compile, 1);

    //rb_define_method(rb_cOnigmo, "fuck", thing, 0);

    VALUE x;
    //x = rb_str_new_cstr("<div>"); // Example html string.

    x = rb_str_new_cstr("a"); // Simple regex

    VALUE obj = rb_class_new_instance(0, NULL, cFoo);
    // rb_funcall(obj, rb_intern("parse"), 1, x);

    // VALUE obj2 = rb_class_new_instance(0, NULL, rb_cOnigmo);

    // obj

    rb_funcall(obj, rb_intern("fuck"), 0);


    //rb_funcall(obj, rb_intern("parse"), 1, x);








    

    VALUE rb_cOnigmo = rb_define_module("Onigmo");
    rb_define_singleton_method(rb_cOnigmo, "parse", parse, 1);
    rb_define_singleton_method(rb_cOnigmo, "compile", compile, 1);

    rb_cOnigmoNode = rb_define_class_under(rb_cOnigmo, "Node", rb_cObject);
    rb_cOnigmoAlternationNode = rb_define_class_under(rb_cOnigmo, "AlternationNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorBufferBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorBufferBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorBufferEndNode = rb_define_class_under(rb_cOnigmo, "AnchorBufferEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorKeepNode = rb_define_class_under(rb_cOnigmo, "AnchorKeepNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorLineBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorLineBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorLineEndNode = rb_define_class_under(rb_cOnigmo, "AnchorLineEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorPositionBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorPositionBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorSemiEndNode = rb_define_class_under(rb_cOnigmo, "AnchorSemiEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorWordBoundaryNode = rb_define_class_under(rb_cOnigmo, "AnchorWordBoundaryNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorWordBoundaryInvertNode = rb_define_class_under(rb_cOnigmo, "AnchorWordBoundaryInvertNode", rb_cOnigmoNode);
    rb_cOnigmoAnyNode = rb_define_class_under(rb_cOnigmo, "AnyNode", rb_cOnigmoNode);
    rb_cOnigmoBackrefNode = rb_define_class_under(rb_cOnigmo, "BackrefNode", rb_cOnigmoNode);
    rb_cOnigmoCallNode = rb_define_class_under(rb_cOnigmo, "CallNode", rb_cOnigmoNode);
    rb_cOnigmoCClassNode = rb_define_class_under(rb_cOnigmo, "CClassNode", rb_cOnigmoNode);
    rb_cOnigmoCClassInvertNode = rb_define_class_under(rb_cOnigmo, "CClassInvertNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseAbsentNode = rb_define_class_under(rb_cOnigmo, "EncloseAbsentNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseConditionNode = rb_define_class_under(rb_cOnigmo, "EncloseConditionNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseMemoryNode = rb_define_class_under(rb_cOnigmo, "EncloseMemoryNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseOptionsNode = rb_define_class_under(rb_cOnigmo, "EncloseOptionsNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseStopBacktrackNode = rb_define_class_under(rb_cOnigmo, "EncloseStopBacktrackNode", rb_cOnigmoNode);
    rb_cOnigmoListNode = rb_define_class_under(rb_cOnigmo, "ListNode", rb_cOnigmoNode);
    rb_cOnigmoLookAheadNode = rb_define_class_under(rb_cOnigmo, "LookAheadNode", rb_cOnigmoNode);
    rb_cOnigmoLookAheadInvertNode = rb_define_class_under(rb_cOnigmo, "LookAheadInvertNode", rb_cOnigmoNode);
    rb_cOnigmoLookBehindNode = rb_define_class_under(rb_cOnigmo, "LookBehindNode", rb_cOnigmoNode);
    rb_cOnigmoLookBehindInvertNode = rb_define_class_under(rb_cOnigmo, "LookBehindInvertNode", rb_cOnigmoNode);
    rb_cOnigmoQuantifierNode = rb_define_class_under(rb_cOnigmo, "QuantifierNode", rb_cOnigmoNode);
    rb_cOnigmoStringNode = rb_define_class_under(rb_cOnigmo, "StringNode", rb_cOnigmoNode);
    rb_cOnigmoWordNode = rb_define_class_under(rb_cOnigmo, "WordNode", rb_cOnigmoNode);
    rb_cOnigmoWordInvertNode = rb_define_class_under(rb_cOnigmo, "WordInvertNode", rb_cOnigmoNode);

    //rb_define_method(rb_cOnigmo, "fuck", thing, 0);


    VALUE obj3 = rb_class_new_instance(0, NULL, rb_cOnigmo);


    // rb_funcall(rb_cOnigmo, rb_intern("parse"), 1, x);

    // VALUE obj2 = rb_class_new_instance(0, NULL, rb_cOnigmo);

    // obj

    //rb_funcall(obj3, rb_intern("fuck"), 0);







    //rb_funcall(obj2, rb_intern("fuck"), 0);

    //rb_funcall(obj2, rb_intern("parse"), 1, x);
    
    //return 0;
    return ruby_cleanup(0);
}




```

and it crashes on this line: `VALUE obj3 = rb_class_new_instance(0, NULL, rb_cOnigmo);`

here is the gdb backtrace:

```

Reading symbols from ./fuzzer...
(gdb) r
Starting program: /home/cyberhacker/Asioita/Hakkerointi/Fuzzing/onigmo/ext/onigmo/fuzzer 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7cbeca9 in ?? () from /lib/x86_64-linux-gnu/libruby-3.0.so.3.0
(gdb) where
#0  0x00007ffff7cbeca9 in ?? () from /lib/x86_64-linux-gnu/libruby-3.0.so.3.0
#1  0x00007ffff7cc4502 in ?? () from /lib/x86_64-linux-gnu/libruby-3.0.so.3.0
#2  0x00007ffff7cc4662 in rb_exc_raise () from /lib/x86_64-linux-gnu/libruby-3.0.so.3.0
#3  0x00007ffff7cbaa0b in ?? () from /lib/x86_64-linux-gnu/libruby-3.0.so.3.0
#4  0x00007ffff7c45ccb in rb_check_type () from /lib/x86_64-linux-gnu/libruby-3.0.so.3.0
#5  0x00007ffff7c46c7b in ?? () from /lib/x86_64-linux-gnu/libruby-3.0.so.3.0
#6  0x000055555555c763 in main (argc=<optimized out>, argv=<optimized out>) at onigmo.c:1149


```

as you can see, there is a call to rb_check_type which I guess checks the type???? Therefore I think that I am somehow calling the rb_class_new_instance function wrong. See, I am calling the function with a module as argument.

See, if I try to call `VALUE obj3 = rb_class_new_instance(0, NULL, rb_cOnigmoLookAheadNode);` it works fine.

## How to create instance of module in ruby C api ???????

I looked absolutely everywhere on how to call a module from c code, but I can't find one single good tutorial on this. Maybe I should ask a question on stackoverflow?

After doing some code cleanup, I now have this as my wrapper code:

```

int main(int argc, char** argv) {
    // Initialize ruby
    ruby_init();

    // Define example regex string
    VALUE x;
    x = rb_str_new_cstr("a"); // Very simple regex which maches an "a" character

    
    // Initialize the Onigmo module
    printf("Initializing the Onigmo module...\n");

    VALUE rb_cOnigmo = rb_define_module("Onigmo");

    rb_define_singleton_method(rb_cOnigmo, "parse", parse, 1);
    rb_define_singleton_method(rb_cOnigmo, "compile", compile, 1);

    rb_cOnigmoNode = rb_define_class_under(rb_cOnigmo, "Node", rb_cObject);
    rb_cOnigmoAlternationNode = rb_define_class_under(rb_cOnigmo, "AlternationNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorBufferBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorBufferBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorBufferEndNode = rb_define_class_under(rb_cOnigmo, "AnchorBufferEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorKeepNode = rb_define_class_under(rb_cOnigmo, "AnchorKeepNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorLineBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorLineBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorLineEndNode = rb_define_class_under(rb_cOnigmo, "AnchorLineEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorPositionBeginNode = rb_define_class_under(rb_cOnigmo, "AnchorPositionBeginNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorSemiEndNode = rb_define_class_under(rb_cOnigmo, "AnchorSemiEndNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorWordBoundaryNode = rb_define_class_under(rb_cOnigmo, "AnchorWordBoundaryNode", rb_cOnigmoNode);
    rb_cOnigmoAnchorWordBoundaryInvertNode = rb_define_class_under(rb_cOnigmo, "AnchorWordBoundaryInvertNode", rb_cOnigmoNode);
    rb_cOnigmoAnyNode = rb_define_class_under(rb_cOnigmo, "AnyNode", rb_cOnigmoNode);
    rb_cOnigmoBackrefNode = rb_define_class_under(rb_cOnigmo, "BackrefNode", rb_cOnigmoNode);
    rb_cOnigmoCallNode = rb_define_class_under(rb_cOnigmo, "CallNode", rb_cOnigmoNode);
    rb_cOnigmoCClassNode = rb_define_class_under(rb_cOnigmo, "CClassNode", rb_cOnigmoNode);
    rb_cOnigmoCClassInvertNode = rb_define_class_under(rb_cOnigmo, "CClassInvertNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseAbsentNode = rb_define_class_under(rb_cOnigmo, "EncloseAbsentNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseConditionNode = rb_define_class_under(rb_cOnigmo, "EncloseConditionNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseMemoryNode = rb_define_class_under(rb_cOnigmo, "EncloseMemoryNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseOptionsNode = rb_define_class_under(rb_cOnigmo, "EncloseOptionsNode", rb_cOnigmoNode);
    rb_cOnigmoEncloseStopBacktrackNode = rb_define_class_under(rb_cOnigmo, "EncloseStopBacktrackNode", rb_cOnigmoNode);
    rb_cOnigmoListNode = rb_define_class_under(rb_cOnigmo, "ListNode", rb_cOnigmoNode);
    rb_cOnigmoLookAheadNode = rb_define_class_under(rb_cOnigmo, "LookAheadNode", rb_cOnigmoNode);
    rb_cOnigmoLookAheadInvertNode = rb_define_class_under(rb_cOnigmo, "LookAheadInvertNode", rb_cOnigmoNode);
    rb_cOnigmoLookBehindNode = rb_define_class_under(rb_cOnigmo, "LookBehindNode", rb_cOnigmoNode);
    rb_cOnigmoLookBehindInvertNode = rb_define_class_under(rb_cOnigmo, "LookBehindInvertNode", rb_cOnigmoNode);
    rb_cOnigmoQuantifierNode = rb_define_class_under(rb_cOnigmo, "QuantifierNode", rb_cOnigmoNode);
    rb_cOnigmoStringNode = rb_define_class_under(rb_cOnigmo, "StringNode", rb_cOnigmoNode);
    rb_cOnigmoWordNode = rb_define_class_under(rb_cOnigmo, "WordNode", rb_cOnigmoNode);
    rb_cOnigmoWordInvertNode = rb_define_class_under(rb_cOnigmo, "WordInvertNode", rb_cOnigmoNode);



    printf("Creating instance of rb_cOnigmo...\n");
    VALUE module_object = rb_class_new_instance(0, NULL, rb_cOnigmo);
    printf("Trying to call \"parse\" on the module...\n");
    rb_funcall(module_object, rb_intern("parse"), 1, x);
    printf("Done!\n");


    return ruby_cleanup(0);
}

```

Let's ask a question! Basically we want to accomplish this:

```
Onigmo.parse("a")
```

After a bit of formatting, I now have this: https://stackoverflow.com/questions/78215259/how-to-call-a-method-of-a-module-properly-in-ruby-c-api . Feel free to answer if you know what to do.

Now I am just going to wait until someone (hopefully) answers my question...


























