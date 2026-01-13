
# Day 22

## Part 1


This is quite a fun little challenge. I am going to try to solve it in rust, because I want to learn rust.

My first thought is to parse the input as a list of lists with a list of "offsets" for the lines which do not start from the start.

Ok so I am probably two hours in and I am still trying to figure out how to parse the input.

After a bit of typing here is basically my first attempt to program rust: (I have read some rust code but never wrote.) :

{% raw %}
```


use std::io;


// Thanks to https://stackoverflow.com/questions/56921637/how-do-i-split-a-string-using-a-rust-regex-and-keep-the-delimiters

use regex::Regex; // 1.1.8

fn split_keep<'a>(r: &Regex, text: &'a str) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut last = 0;
    for (index, matched) in text.match_indices(r) {
        if last != index {
            result.push(&text[last..index]);
        }
        result.push(matched);
        last = index + matched.len();
    }
    if last < text.len() {
        result.push(&text[last..]);
    }
    result
}


fn parse_input() -> (Vec<i32>, Vec<i32>) {

    // Go through all the lines in stdin

    //let out_map: Vec<i32> = Vec::new();

    let out_map = Vec::new();

    let moves: Vec<i32> = Vec::new();

    let line_offsets: Vec<i32> = Vec::new();

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines()

    loop {
        //println!("{}", line.unwrap());

        let cur_line = lines.next().unwrap().unwrap(); 

        if cur_line.eq("\n") {

            break;

        }




        let current_chars: Vec<i32> = String::from(cur_line).chars(); // Get string.

        let offset: i32 = 0;

        // Calculate offset

        loop {
            
            if !current_chars[offset].eq(" ") {

                break;

            }
            offset++;

        }

        // Append to offsets.

        line_offsets.append(offset);

        // let last3 = v.as_slice()[v.len()-3..].to_vec();
        // thanks to https://stackoverflow.com/questions/44549759/return-last-n-elements-of-vector-in-rust-without-mutating-the-vector

        let new_line: Vec<i32> = Vec::new();

        for c in v.as_slice()[offset..].to_vec() {

            if c == 46 { // ascii character code of 46 is the dot character (".")
                new_line.append(1);
            } else {
                // assume "#" character.

                new_line.append(0);

            }


        }

        out_map.append(new_line);

    }


    let move_line = lines.next().unwrap().unwrap(); 

    // now the very last line is the line which tells all of the moves and stuff.

    // Extract integers and moves from string.
    let seperator = Regex::new(r"R|L").expect("Invalid regex");

    let move_stuff = split_keep(move_line);

    let move_lenghts: Vec<i32> = Vec::new();

    let count: i32 = 0;

    for m in move_stuff {
        if count % 2 == 0 {

            move_lenghts.append(m.parse::<i32>().unwrap(););  // modulo two equals zero means length.

        } else {

            assert!(m.eq("L") || m.eq("R")); // Only left and right moves are allowed.
            if m.eq("L") {

                moves.append(0); // 0 == left
            } else {
                moves.append(1); // 1 == right
            }
            //moves.append(m);
        }

        count++:

        //move_lenghts.append()

    }






    (out_map, line_offsets, moves, move_lenghts);

}

fn main() {
    
    let (game_map: Vec<i32>, line_offsets: Vec<i32>, moves: Vec<i32>, move_lenghts: Vec<i32>) = parse_input();

    




}



```
{% endraw %}

This code results in these errors:

{% raw %}
```

error: expected `;`, found keyword `loop`
  --> src/main.rs:39:41
   |
39 |     let mut lines = stdin.lock().lines()
   |                                         ^ help: add `;` here
40 |
41 |     loop {
   |     ---- unexpected token

error: Rust has no postfix increment operator
  --> src/main.rs:68:19
   |
68 |             offset++;
   |                   ^^ not a valid postfix operator
   |
help: use `+= 1` instead
   |
68 |             { let tmp = offset; offset += 1; tmp };
   |             +++++++++++       ~~~~~~~~~~~~~~~~~~~~
68 |             offset += 1;
   |                    ~~~~

error: expected one of `)`, `,`, `.`, `?`, or an operator, found `;`
   --> src/main.rs:116:58
    |
116 |             move_lenghts.append(m.parse::<i32>().unwrap(););  // modulo two equals zero means length.
    |                                                          ^ expected one of `)`, `,`, `.`, `?`, or an operator

error: Rust has no postfix increment operator
   --> src/main.rs:130:14
    |
130 |         count++:
    |              ^^ not a valid postfix operator
    |
help: use `+= 1` instead
    |
130 |         { let tmp = count; count += 1; tmp }:
    |         +++++++++++      ~~~~~~~~~~~~~~~~~~~
130 |         count += 1:
    |               ~~~~

error: expected one of `)`, `,`, `@`, or `|`, found `:`
   --> src/main.rs:147:18
    |
147 |     let (game_map: Vec<i32>, line_offsets: Vec<i32>, moves: Vec<i32>, move_lenghts: Vec<i32>) = parse_input();
    |                  ^ expected one of `)`, `,`, `@`, or `|`

error: expected one of `!`, `+`, `::`, `;`, or `=`, found `,`
   --> src/main.rs:147:28
    |
147 |     let (game_map: Vec<i32>, line_offsets: Vec<i32>, moves: Vec<i32>, move_lenghts: Vec<i32>) = parse_input();
    |                            ^ expected one of `!`, `+`, `::`, `;`, or `=`

error[E0432]: unresolved import `regex`
 --> src/main.rs:7:5
  |
7 | use regex::Regex; // 1.1.8
  |     ^^^^^ use of undeclared crate or module `regex`

error[E0425]: cannot find value `v` in this scope
  --> src/main.rs:81:18
   |
81 |         for c in v.as_slice()[offset..].to_vec() {
   |                  ^ not found in this scope

error[E0599]: no method named `lines` found for struct `StdinLock` in the current scope
  --> src/main.rs:39:34
   |
39 |     let mut lines = stdin.lock().lines()
   |                                  ^^^^^ method not found in `StdinLock<'static>`
   |
   = help: items from traits can only be used if the trait is in scope
help: the following trait is implemented but not in scope; perhaps add a `use` for it:
   |
2  | use std::io::BufRead;
   |

error[E0308]: mismatched types
  --> src/main.rs:55:39
   |
55 |         let current_chars: Vec<i32> = String::from(cur_line).chars(); // Get string.
   |                            --------   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ expected struct `Vec`, found struct `Chars`
   |                            |
   |                            expected due to this
   |
   = note: expected struct `Vec<i32>`
              found struct `Chars<'_>`

error[E0277]: the type `[i32]` cannot be indexed by `i32`
  --> src/main.rs:63:31
   |
63 |             if !current_chars[offset].eq(" ") {
   |                               ^^^^^^ slice indices are of type `usize` or ranges of `usize`
   |
   = help: the trait `SliceIndex<[i32]>` is not implemented for `i32`
   = help: the trait `SliceIndex<[T]>` is implemented for `usize`
   = note: required for `Vec<i32>` to implement `Index<i32>`

error[E0308]: mismatched types
  --> src/main.rs:74:29
   |
74 |         line_offsets.append(offset);
   |                      ------ ^^^^^^ expected `&mut Vec<i32>`, found `i32`
   |                      |
   |                      arguments to this function are incorrect
   |
   = note: expected mutable reference `&mut Vec<i32>`
                           found type `i32`
note: associated function defined here

error[E0308]: mismatched types
  --> src/main.rs:84:33
   |
84 |                 new_line.append(1);
   |                          ------ ^ expected `&mut Vec<i32>`, found integer
   |                          |
   |                          arguments to this function are incorrect
   |
   = note: expected mutable reference `&mut Vec<i32>`
                           found type `{integer}`
note: associated function defined here

error[E0308]: mismatched types
  --> src/main.rs:88:33
   |
88 |                 new_line.append(0);
   |                          ------ ^ expected `&mut Vec<i32>`, found integer
   |                          |
   |                          arguments to this function are incorrect
   |
   = note: expected mutable reference `&mut Vec<i32>`
                           found type `{integer}`
note: associated function defined here

error[E0308]: mismatched types
  --> src/main.rs:95:24
   |
95 |         out_map.append(new_line);
   |                 ------ ^^^^^^^^
   |                 |      |
   |                 |      expected `&mut Vec<_>`, found struct `Vec`
   |                 |      help: consider mutably borrowing here: `&mut new_line`
   |                 arguments to this function are incorrect
   |
   = note: expected mutable reference `&mut Vec<_>`
                         found struct `Vec<i32>`
note: associated function defined here

error[E0061]: this function takes 2 arguments but 1 argument was supplied
   --> src/main.rs:107:22
    |
107 |     let move_stuff = split_keep(move_line);
    |                      ^^^^^^^^^^----------- an argument of type `&str` is missing
    |
note: function defined here
   --> src/main.rs:9:4
    |
9   | fn split_keep<'a>(r: &Regex, text: &'a str) -> Vec<&'a str> {
    |    ^^^^^^^^^^     ---------  -------------
help: provide the argument
    |
107 |     let move_stuff = split_keep(move_line, /* &str */);
    |                                ~~~~~~~~~~~~~~~~~~~~~~~

error[E0308]: mismatched types
   --> src/main.rs:116:33
    |
116 |             move_lenghts.append(m.parse::<i32>().unwrap(););  // modulo two equals zero means length.
    |                          ------ ^^^^^^^^^^^^^^^^^^^^^^^^^ expected `&mut Vec<i32>`, found `i32`
    |                          |
    |                          arguments to this function are incorrect
    |
    = note: expected mutable reference `&mut Vec<i32>`
                            found type `i32`
note: associated function defined here

error[E0308]: mismatched types
   --> src/main.rs:123:30
    |
123 |                 moves.append(0); // 0 == left
    |                       ------ ^ expected `&mut Vec<i32>`, found integer
    |                       |
    |                       arguments to this function are incorrect
    |
    = note: expected mutable reference `&mut Vec<i32>`
                            found type `{integer}`
note: associated function defined here

error[E0308]: mismatched types
   --> src/main.rs:125:30
    |
125 |                 moves.append(1); // 1 == right
    |                       ------ ^ expected `&mut Vec<i32>`, found integer
    |                       |
    |                       arguments to this function are incorrect
    |
    = note: expected mutable reference `&mut Vec<i32>`
                            found type `{integer}`
note: associated function defined here

error[E0308]: mismatched types
   --> src/main.rs:26:21
    |
26  | fn parse_input() -> (Vec<i32>, Vec<i32>) {
    |    -----------      ^^^^^^^^^^^^^^^^^^^^ expected tuple, found `()`
    |    |
    |    implicitly returns `()` as its body has no tail or `return` expression
    |
    = note:  expected tuple `(Vec<i32>, Vec<i32>)`
            found unit type `()`
note: consider returning one of these bindings
   --> src/main.rs:100:9
    |
100 |     let move_line = lines.next().unwrap().unwrap(); 
    |         ^^^^^^^^^
...
105 |     let seperator = Regex::new(r"R|L").expect("Invalid regex");
    |         ^^^^^^^^^

Some errors have detailed explanations: E0061, E0277, E0308, E0425, E0432, E0599.
For more information about an error, try `rustc --explain E0061`.
error: could not compile `solution` due to 20 previous errors



```
{% endraw %}

Only 20 errors? That is surprisingly good for our first ever program.

After a bit of modifying I ended up with this:

{% raw %}
```

//use std::io;
use std::io::{self, BufRead};

// Thanks to https://stackoverflow.com/questions/56921637/how-do-i-split-a-string-using-a-rust-regex-and-keep-the-delimiters

use regex::Regex; // 1.1.8

fn split_keep<'a>(r: &Regex, text: &'a str) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut last = 0;
    for (index, matched) in text.match_indices(r) {
        if last != index {
            result.push(&text[last..index]);
        }
        result.push(matched);
        last = index + matched.len();
    }
    if last < text.len() {
        result.push(&text[last..]);
    }
    result
}


fn parse_input() -> (Vec<Vec<i32>>, Vec<i32>, Vec<i32>, Vec<i32>) {

    // Go through all the lines in stdin

    //let out_map: Vec<i32> = Vec::new();

    let out_map = Vec::new();

    let moves: Vec<i32> = Vec::new();

    let line_offsets: Vec<i32> = Vec::new();

    let stdin = io::stdin();
    //let mut lines = stdin.lock().lines();

    let mut lines = stdin.lock().lines();



    loop {
        //println!("{}", line.unwrap());

        let cur_line = lines.next().unwrap().unwrap(); 

        if cur_line.eq("\n") {

            break;

        }




        //let current_chars: Vec<i32> = String::from(cur_line).chars(); // Get string.

        // rent_chars[offset as usize].eq(


        //let current_chars: std::str::Chars = String::from(cur_line).chars().to_vec();

        let current_chars: Vec<char> = String::from(cur_line).chars().collect();

        let mut offset: i32 = 0;

        // Calculate offset

        loop {
            
            //if !current_chars[offset as usize].eq(" ") {

            if !(current_chars[offset as usize]== 32 as char) {
                break;

            }
            offset += 1;

        }

        // Append to offsets.

        line_offsets.push(offset);

        // let last3 = v.as_slice()[v.len()-3..].to_vec();
        // thanks to https://stackoverflow.com/questions/44549759/return-last-n-elements-of-vector-in-rust-without-mutating-the-vector

        let new_line: Vec<i32> = Vec::new();

        for c in new_line.as_slice()[offset as usize..].to_vec() {

            if c == 46 { // ascii character code of 46 is the dot character (".")
                new_line.push(1);
            } else {
                // assume "#" character.

                new_line.push(0);

            }


        }

        out_map.push(new_line);

    }


    let move_line = lines.next().unwrap().unwrap(); 

    // now the very last line is the line which tells all of the moves and stuff.

    // Extract integers and moves from string.

    //     let seperator = Regex::new(r"([ ,.]+)").expect("Invalid regex");

    let seperator = Regex::new(r"R|L").expect("Invalid regex");

    let move_stuff = split_keep(&seperator, &move_line);

    let move_lenghts: Vec<i32> = Vec::new();

    let count: i32 = 0;

    for m in move_stuff {
        if count % 2 == 0 {

            move_lenghts.push(m.parse::<i32>().unwrap());  // modulo two equals zero means length.

        } else {

            assert!(m.eq("L") || m.eq("R")); // Only left and right moves are allowed.
            if m.eq("L") {

                moves.push(0); // 0 == left
            } else {
                moves.push(1); // 1 == right
            }
            //moves.append(m);
        }

        count += 1;

        //move_lenghts.append()

    }






    //(out_map, line_offsets, moves, move_lenghts);

    (out_map, line_offsets, moves, move_lenghts)

}

fn main() {
    
    //let (game_map: Vec<i32>, line_offsets: Vec<i32>, moves: Vec<i32>, move_lenghts: Vec<i32>) = parse_input();

    //let (game_map, line_offsets, moves, move_lenghts) = parse_input();
    let res = parse_input();



}




```
{% endraw %}

This generates more errors:

{% raw %}
```

   Compiling solution v0.1.0 (/home/cyberhacker/Asioita/Ohjelmointi/adventofcode2022/chapter_22/solution)
error[E0596]: cannot borrow `moves` as mutable, as it is not declared as mutable
   --> src/main.rs:34:9
    |
34  |     let moves: Vec<i32> = Vec::new();
    |         ^^^^^ not mutable
...
138 |                 moves.push(0); // 0 == left
    |                 ------------- cannot borrow as mutable
139 |             } else {
140 |                 moves.push(1); // 1 == right
    |                 ------------- cannot borrow as mutable
    |
help: consider changing this to be mutable
    |
34  |     let mut moves: Vec<i32> = Vec::new();
    |         +++

error[E0596]: cannot borrow `line_offsets` as mutable, as it is not declared as mutable
  --> src/main.rs:86:9
   |
86 |         line_offsets.push(offset);
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^ cannot borrow as mutable
   |
help: consider changing this to be mutable
   |
36 |     let mut line_offsets: Vec<i32> = Vec::new();
   |         +++

error[E0596]: cannot borrow `new_line` as mutable, as it is not declared as mutable
   --> src/main.rs:91:13
    |
91  |         let new_line: Vec<i32> = Vec::new();
    |             ^^^^^^^^ not mutable
...
96  |                 new_line.push(1);
    |                 ---------------- cannot borrow as mutable
...
100 |                 new_line.push(0);
    |                 ---------------- cannot borrow as mutable
    |
help: consider changing this to be mutable
    |
91  |         let mut new_line: Vec<i32> = Vec::new();
    |             +++

error[E0596]: cannot borrow `out_map` as mutable, as it is not declared as mutable
   --> src/main.rs:107:9
    |
107 |         out_map.push(new_line);
    |         ^^^^^^^^^^^^^^^^^^^^^^ cannot borrow as mutable
    |
help: consider changing this to be mutable
    |
32  |     let mut out_map = Vec::new();
    |         +++

error[E0596]: cannot borrow `move_lenghts` as mutable, as it is not declared as mutable
   --> src/main.rs:131:13
    |
131 |             move_lenghts.push(m.parse::<i32>().unwrap());  // modulo two equals zero means length.
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cannot borrow as mutable
    |
help: consider changing this to be mutable
    |
124 |     let mut move_lenghts: Vec<i32> = Vec::new();
    |         +++

error[E0384]: cannot assign twice to immutable variable `count`
   --> src/main.rs:145:9
    |
126 |     let count: i32 = 0;
    |         -----
    |         |
    |         first assignment to `count`
    |         help: consider making this binding mutable: `mut count`
...
145 |         count += 1;
    |         ^^^^^^^^^^ cannot assign twice to immutable variable




```
{% endraw %}

Here is the final version of the program which actually works:


{% raw %}
```


//use std::io;
use std::io::{self, BufRead};

// Thanks to https://stackoverflow.com/questions/56921637/how-do-i-split-a-string-using-a-rust-regex-and-keep-the-delimiters

use regex::Regex; // 1.1.8

fn split_keep<'a>(r: &Regex, text: &'a str) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut last = 0;
    for (index, matched) in text.match_indices(r) {
        if last != index {
            result.push(&text[last..index]);
        }
        result.push(matched);
        last = index + matched.len();
    }
    if last < text.len() {
        result.push(&text[last..]);
    }
    result
}


fn parse_input() -> (Vec<Vec<i32>>, Vec<i32>, Vec<i32>, Vec<i32>) {

    // Go through all the lines in stdin

    //let out_map: Vec<i32> = Vec::new();

    let mut out_map = Vec::new();

    let mut moves: Vec<i32> = Vec::new();

    let mut line_offsets: Vec<i32> = Vec::new();

    let stdin = io::stdin();
    //let mut lines = stdin.lock().lines();

    let mut lines = stdin.lock().lines();



    loop {
        //println!("{}", line.unwrap());

        let cur_line = lines.next().unwrap().unwrap(); 
        println!("Current line: {}\n", cur_line);
        if cur_line.eq("") {

            break;

        }




        //let current_chars: Vec<i32> = String::from(cur_line).chars(); // Get string.

        // rent_chars[offset as usize].eq(


        //let current_chars: std::str::Chars = String::from(cur_line).chars().to_vec();

        let current_chars: Vec<char> = String::from(cur_line).chars().collect();

        let mut offset: i32 = 0;

        // Calculate offset

        loop {
            
            //if !current_chars[offset as usize].eq(" ") {
            println!("{}", offset);
            if !(current_chars[offset as usize]== 32 as char) {
                break;

            }
            offset += 1;

        }

        // Append to offsets.

        line_offsets.push(offset);

        // let last3 = v.as_slice()[v.len()-3..].to_vec();
        // thanks to https://stackoverflow.com/questions/44549759/return-last-n-elements-of-vector-in-rust-without-mutating-the-vector

        let mut new_line: Vec<i32> = Vec::new();

        //for c in new_line.as_slice()[offset as usize..].to_vec() {
        for c in current_chars.as_slice()[offset as usize..].to_vec() {

            if c == 46 as char { // ascii character code of 46 is the dot character (".")
                new_line.push(1);
            } else {
                // assume "#" character.

                new_line.push(0);

            }


        }

        out_map.push(new_line);

    }


    let move_line = lines.next().unwrap().unwrap(); 

    // now the very last line is the line which tells all of the moves and stuff.

    // Extract integers and moves from string.

    //     let seperator = Regex::new(r"([ ,.]+)").expect("Invalid regex");

    let seperator = Regex::new(r"R|L").expect("Invalid regex");

    let move_stuff = split_keep(&seperator, &move_line);

    let mut move_lenghts: Vec<i32> = Vec::new();

    let mut count: i32 = 0;

    for m in move_stuff {
        if count % 2 == 0 {

            move_lenghts.push(m.parse::<i32>().unwrap());  // modulo two equals zero means length.

        } else {

            assert!(m.eq("L") || m.eq("R")); // Only left and right moves are allowed.
            if m.eq("L") {

                moves.push(0); // 0 == left
            } else {
                moves.push(1); // 1 == right
            }
            //moves.append(m);
        }

        count += 1;

        //move_lenghts.append()

    }






    //(out_map, line_offsets, moves, move_lenghts);

    (out_map, line_offsets, moves, move_lenghts)

}

fn main() {
    
    //let (game_map: Vec<i32>, line_offsets: Vec<i32>, moves: Vec<i32>, move_lenghts: Vec<i32>) = parse_input();

    //let (game_map, line_offsets, moves, move_lenghts) = parse_input();
    let (game_map, line_offsets, moves, move_lenghts) = parse_input();



}



```
{% endraw %}


Now it is time to move on to actually solving the problem! :)

I think I am just going to make a loop which goes through all of the moves and stuff. (I don't think there is that much optimization here because the only optimization I can think of is using modular arithmetic instead of marking the walls as "loop around points". Another optimization I think is the optimization to instead of using a vec of vecs, we just access a vec with the x and y coordinates, but that complicates things because not all rows are of the same size so I do not think that it will be worth it in this case. I think that to get the length of a rust vec it is O(n) not O(1) like in python (python stores the list length as and updates it on the fly when you are modifying the list) . Wait nevermind. rust also keeps track of the length of the vector: https://stackoverflow.com/questions/49775759/what-is-the-runtime-complexity-of-veclen  ) .


Now it is time to program the mainloop:



------------

Ok so lets just skip ahead a bit.

My first thought was to use modulos when computing the position for every step, but then I realized that when moving from columns which are of different lengths, this method "teleports". This was my first attempt:


{% raw %}
```


fn main_loop(game_map: Vec<Vec<i32>>, line_offsets: Vec<i32>, mut moves: Vec<i32>, move_lenghts: Vec<i32>, vertical_offsets: Vec<i32>, vertical_lengths: Vec<i32>) {

    let mut cur_x: i32 = line_offsets[0]; // This must be here because we start on the top.
    let mut cur_y: i32 = 0;

    let mut distance: i32 = 0;

    let mut turn = 0;

    let mut facing = 0;  // "Facing is 0 for right (>), 1 for down (v), 2 for left (<), and 3 for up (^)."

    let mut counter = 0;

    let mut dx = 0;

    let mut dy = 0;

    let mut x_access = 0;

    let mut y_access = 0;

    moves.push(1); // final move does not matter

    for m in moves {

        // Mainloop

        distance = move_lenghts[counter];

        // Try to go forward

        match facing {
            0 => {
                dx = 1;
                dy = 0;
            }
            1 => {
                dx = 0;
                dy = 1;  // Y is one on the highest level and the biggest on the ground.
            }
            2 => {
                dx = -1;
                dy = 0;
            }
            3 => {
                dx = 0;
                dy = -1;
            }
            _ => {
                assert!(false); // shouldn't happen.
            }
        }

        // Try to advance
        println!("facing == {}", facing);
        println!("distance == {}", distance);
        for n in 0..distance {


            cur_x += dx;

            cur_y += dy;

            // check block

            // actual place is cur_x, (line_offsets[cur_y]+cur_x)%game_map[cur_y].len()

            println!("cur_y: {}", cur_y);
            println!("cur_x: {}", cur_x);
            //println!("game_map.len() == {}\n",game_map.len());
            //if game_map[(cur_y as usize % game_map.len()) as usize][((line_offsets[(cur_y as usize % game_map.len()) as usize]+cur_x)%(game_map[(cur_y as usize % game_map.len()) as usize].len()) as i32) as usize] == 1 {

            x_access = ((line_offsets[(cur_y as usize % game_map.len()) as usize]+cur_x)%(game_map[(cur_y as usize % game_map.len()) as usize].len()) as i32) as usize;
            
            //y_access = (cur_y as usize % game_map.len()) as usize
            
            y_access = ((vertical_offsets[(cur_x as usize % game_map[cur_y as usize].len()) as usize]+cur_y)%(game_map[(cur_x as usize % game_map[cur_y as usize].len()) as usize].len()) as i32) as usize;
            

            
            if game_map[y_access][x_access] == 1 {
                // Blocked

                cur_y -= dy;

                cur_x -= dx;

                break


            }

        
        }

        if m == 0 {
            facing -= 1; // left
            facing = facing % 4;
        } else {
            // assume right
            facing += 1;
            facing = facing % 4;
        }



        
        counter += 1;



    }
    facing -= 1; // reset the facing because we add one on the last cycle
    println!("Final x: {}\n", cur_x);
    println!("Final y: {}\n", cur_y);


}


```
{% endraw %}


the reason why my code did not work wasn't because of some singular bug, but that my understanding of the movement itself was flawed from the start.

The next idea was to just instead of using modulos the calculate the position and keeping the coordinates to be "free floating" aka we could be at x -1000 and y 200000, instead of that and then using modular arithmetic to get the "actual" position, i just simply decided to modify the coordinates themselves and teleport. We can do this because we know the length of each row and column and their offsets. This assumes that there is only one continues segment of places where we can be at any row or column, for example this pattern would not be allowed:


{% raw %}
```

...
.. 
...
...

```
{% endraw %}

because there is an empty space where we can not go and then spaces where we can go again  on the same column.


Here is my final code which was a lot simpler than my initial approach:


{% raw %}
```



fn main_loop(game_map: Vec<Vec<i32>>, line_offsets: Vec<i32>, mut moves: Vec<i32>, move_lenghts: Vec<i32>, vertical_offsets: Vec<i32>, vertical_lengths: Vec<i32>) -> i32 {

    let mut cur_x: i32 = line_offsets[0]; // This must be here because we start on the top.
    let mut cur_y: i32 = 0;

    let mut distance: i32 = 0;

    let mut turn = 0;

    let mut facing = 0;  // "Facing is 0 for right (>), 1 for down (v), 2 for left (<), and 3 for up (^)."

    let mut counter = 0;

    let mut dx = 0;

    let mut dy = 0;

    let mut x_access = 0;

    let mut y_access = 0;

    let mut prev_x = 0;

    let mut prev_y = 0;

    moves.push(1); // final move does not matter

    for m in moves {

        // Mainloop

        distance = move_lenghts[counter];

        // Try to go forward
        println!("facing == {}", facing);
        match facing {
            0 => {
                dx = 1;
                dy = 0;
            }
            1 => {
                dx = 0;
                dy = 1;  // Y is one on the highest level and the biggest on the ground.
            }
            2 => {
                dx = -1;
                dy = 0;
            }
            3 => {
                dx = 0;
                dy = -1;
            }
            _ => {
                assert!(false); // shouldn't happen.
            }
        }

        // Try to advance
        
        println!("distance == {}", distance);
        for n in 0..distance {



            prev_x = cur_x;

            prev_y = cur_y;

            cur_x += dx;

            cur_y += dy;

            println!("cur_y before check: {}", cur_y);
            println!("cur_x before check: {}", cur_x);

            // check loop.

            // check Y

            /*

            if vertical_offsets[cur_x as usize] > cur_y { // underflow aka go up
                println!("poopoothing1");
                cur_y = (vertical_offsets[cur_x as usize]  as usize + (vertical_lengths[cur_x as usize] as usize) - 1) as i32; // loop back around
            }

            if vertical_offsets[cur_x as usize] + vertical_lengths[cur_x as usize] -1 < cur_y {
                println!("poopoothing2");
                cur_y = (vertical_offsets[cur_x as usize]  as usize) as i32;  // overflow aka go down
            } 

            // check X

            if line_offsets[cur_y as usize] > cur_x {
                cur_x = line_offsets[cur_y as usize]  as i32 + (game_map[cur_y as usize].len() - 1) as i32; // loop to the right when going left
            }

            if line_offsets[cur_y as usize] + (game_map[cur_y as usize].len() as i32) -1 < cur_x {
                cur_x = line_offsets[cur_y as usize]  as i32; // loop to the left when going right
            }

            */

            if vertical_offsets[prev_x as usize] > cur_y { // underflow aka go up
                println!("poopoothing1");
                cur_y = (vertical_offsets[prev_x as usize]  as usize + (vertical_lengths[prev_x as usize] as usize) - 1) as i32; // loop back around
            }

            if vertical_offsets[prev_x as usize] + vertical_lengths[prev_x as usize] -1 < cur_y {
                println!("poopoothing2");
                cur_y = (vertical_offsets[prev_x as usize]  as usize) as i32;  // overflow aka go down
            } 

            // check X

            if line_offsets[prev_y as usize] > cur_x {
                println!("poopoothing3");
                cur_x = line_offsets[prev_y as usize]  as i32 + (game_map[prev_y as usize].len() - 1) as i32; // loop to the right when going left
            }

            if line_offsets[prev_y as usize] + (game_map[prev_y as usize].len() as i32) -1 < cur_x {
                println!("poopoothing4");
                cur_x = line_offsets[prev_y as usize]  as i32; // loop to the left when going right
            }



            println!("line_offsets[cur_y as usize] + (game_map[cur_y as usize].len() as i32) == {}",line_offsets[cur_y as usize] + (game_map[cur_y as usize].len() as i32));

            // check block

            // actual place is cur_x, (line_offsets[cur_y]+cur_x)%game_map[cur_y].len()

            println!("cur_y: {}", cur_y);
            println!("cur_x: {}", cur_x);
            //println!("game_map.len() == {}\n",game_map.len());
            //if game_map[(cur_y as usize % game_map.len()) as usize][((line_offsets[(cur_y as usize % game_map.len()) as usize]+cur_x)%(game_map[(cur_y as usize % game_map.len()) as usize].len()) as i32) as usize] == 1 {

            //x_access = ((line_offsets[(cur_y as usize % game_map.len()) as usize]+cur_x)%(game_map[(cur_y as usize % game_map.len()) as usize].len()) as i32) as usize;
            
            //y_access = (cur_y as usize % game_map.len()) as usize
            
            //println!("(vertical_offsets[(cur_x as usize % game_map[cur_y as usize].len()) as usize]+cur_y) == {}",(vertical_offsets[(cur_x as usize % game_map[cur_y as usize].len()) as usize]+cur_y));

            //println!("(game_map[(cur_x as usize % game_map[cur_y as usize].len()) as usize].len()) == {}", (game_map[(cur_x as usize % game_map[cur_y as usize].len()) as usize].len()));
            // y_access = (offset)+(y%vertical_length)


            //y_access = ((vertical_offsets[(cur_x as usize % game_map[cur_y as usize].len()) as usize]+cur_y)%(game_map[(cur_x as usize % game_map[cur_y as usize].len()) as usize].len()) as i32) as usize;
            
            //y_access = (vertical_offsets[cur_x as usize % vertical_offsets.len()]) + (cur_y % horizontal_lengths[cur_x as usize % vertical_offsets.len()]);


            //println!("access index: {}",cur_x as usize % vertical_offsets.len());
            
            //println!("current vertical offset: {}", vertical_offsets[cur_x as usize % vertical_offsets.len()]);
            //println!("current vertical length: {}",vertical_lengths[cur_x as usize % vertical_offsets.len()]);
            
            //y_access = (vertical_offsets[cur_x as usize % vertical_offsets.len()]) as usize + (cur_y as usize % vertical_lengths[cur_x as usize % vertical_offsets.len()] as usize) as usize;


            //println!("x_access: {}", x_access);
            //println!("y_access: {}", y_access);

            x_access = cur_x - line_offsets[cur_y as usize]; // delete the offset.

            //y_access = cur_y - vertical_offsets[cur_x as usize];

            y_access = cur_y;

            println!("x_access: {}", x_access);
            println!("y_access: {}", y_access);
            println!("game_map[y_access as usize][x_access as usize] == {}",game_map[y_access as usize][x_access as usize]);
            if game_map[y_access as usize][x_access as usize] == 1 {
                // Blocked
                println!("Blocked");
                //cur_y -= dy;

                //cur_x -= dx;

                cur_x = prev_x;
                cur_y = prev_y;

                println!("cur_y: {}", cur_y);
                println!("cur_x: {}", cur_x);

                break


            }

        
        }

        if m == 0 {
            println!("Decrementing facing.");
            println!("Facing before decrement: {}", facing);

            facing -= 1; // left
            println!("Facing after decrement: {}", facing);
            // The precent sign works differently than in python. In python it is the modulo, when as in rust it is the remainder. The modulo and the remainder are the same for non-negative divisors and dividends, but for negative numbers they differ: https://stackoverflow.com/questions/31210357/is-there-a-modulus-not-remainder-function-operation
            // for example -2 % 5 = -2   , but (-2).rem_euclid(5) = 3




            //facing = facing % 4;
            facing = (facing as i32).rem_euclid(4);
            println!("Facing after modulo: {}", facing);
        } else {
            // assume right
            facing += 1;
            facing = (facing as i32).rem_euclid(4);
            //facing = facing % 4;
        }



        
        counter += 1;



    }
    facing -= 1; // reset the facing because we add one on the last cycle
    

    // Need to add one because the coordinates are one base index based

    cur_x += 1;
    cur_y += 1;

    println!("Final x: {}\n", cur_x);
    println!("Final y: {}\n", cur_y);

    let password: i32 = cur_y * 1000 + cur_x * 4 + facing;

    println!("Password should be: {}", password);

    return password;


}



```
{% endraw %}

Here is the complete code which solves part 1:


{% raw %}
```

//use std::io;
use std::io::{self, BufRead};

// Thanks to https://stackoverflow.com/questions/56921637/how-do-i-split-a-string-using-a-rust-regex-and-keep-the-delimiters

use regex::Regex; // 1.1.8

fn split_keep<'a>(r: &Regex, text: &'a str) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut last = 0;
    for (index, matched) in text.match_indices(r) {
        if last != index {
            result.push(&text[last..index]);
        }
        result.push(matched);
        last = index + matched.len();
    }
    if last < text.len() {
        result.push(&text[last..]);
    }
    result
}


fn parse_input() -> (Vec<Vec<i32>>, Vec<i32>, Vec<i32>, Vec<i32>, Vec<i32>, Vec<i32>) {

    // Go through all the lines in stdin

    //let out_map: Vec<i32> = Vec::new();

    let mut out_map = Vec::new();

    let mut moves: Vec<i32> = Vec::new();

    let mut line_offsets: Vec<i32> = Vec::new();

    let stdin = io::stdin();
    //let mut lines = stdin.lock().lines();

    let mut lines = stdin.lock().lines();

    let mut max_x: usize = 0;

    loop {
        //println!("{}", line.unwrap());

        let cur_line = lines.next().unwrap().unwrap(); 
        println!("Current line: {}\n", cur_line);
        if cur_line.eq("") {

            break;

        }




        //let current_chars: Vec<i32> = String::from(cur_line).chars(); // Get string.

        // rent_chars[offset as usize].eq(


        //let current_chars: std::str::Chars = String::from(cur_line).chars().to_vec();

        let current_chars: Vec<char> = String::from(cur_line).chars().collect();
        if current_chars.to_vec().len() > max_x {

            max_x = current_chars.to_vec().len();
        }
        let mut offset: i32 = 0;

        // Calculate offset

        loop {
            
            //if !current_chars[offset as usize].eq(" ") {
            println!("{}", offset);
            if !(current_chars[offset as usize]== 32 as char) {
                break;

            }
            offset += 1;

        }

        // Append to offsets.

        line_offsets.push(offset);

        // let last3 = v.as_slice()[v.len()-3..].to_vec();
        // thanks to https://stackoverflow.com/questions/44549759/return-last-n-elements-of-vector-in-rust-without-mutating-the-vector

        let mut new_line: Vec<i32> = Vec::new();

        //for c in new_line.as_slice()[offset as usize..].to_vec() {
        for c in current_chars.as_slice()[offset as usize..].to_vec() {

            if c == 46 as char { // ascii character code of 46 is the dot character (".")
                new_line.push(0);
            } else {
                // assume "#" character.

                new_line.push(1);

            }


        }

        out_map.push(new_line);

    }


    let move_line = lines.next().unwrap().unwrap(); 

    // now the very last line is the line which tells all of the moves and stuff.

    // Extract integers and moves from string.

    //     let seperator = Regex::new(r"([ ,.]+)").expect("Invalid regex");

    let seperator = Regex::new(r"R|L").expect("Invalid regex");

    let move_stuff = split_keep(&seperator, &move_line);

    let mut move_lenghts: Vec<i32> = Vec::new();

    let mut count: i32 = 0;

    for m in move_stuff {
        if count % 2 == 0 {

            move_lenghts.push(m.parse::<i32>().unwrap());  // modulo two equals zero means length.

        } else {

            assert!(m.eq("L") || m.eq("R")); // Only left and right moves are allowed.
            if m.eq("L") {

                moves.push(0); // 0 == left
            } else {
                moves.push(1); // 1 == right
            }
            //moves.append(m);
        }

        count += 1;

        //move_lenghts.append()

    }


    // Now get the horizontal lengths and offsets.

    let mut horizontal_offsets: Vec<i32> = Vec::new();

    let mut horizontal_lengths: Vec<i32> = Vec::new();

    let mut y_count: i32 = 0;
    let mut intermediate: i32 = 0;
    //for x_count in 0..out_map[0].len() {  // loop through all columns
    for x_count in 0..max_x {  // loop through all columns  
        y_count = 0;
        println!("Looping with x_count {}",x_count);
        println!("max_x == {}",max_x);
        loop {
            println!("line_offsets[y_count as usize] == {:?}", line_offsets[y_count as usize]);
            if (line_offsets[y_count as usize] <= x_count as i32 && line_offsets[y_count as usize] + (out_map[y_count as usize].len() - 1) as i32 >= x_count as i32) || x_count == max_x {
                break;
            }

            y_count += 1;
        }

        horizontal_offsets.push(y_count); // offset to the line start


        //y_count = 0;
        intermediate = y_count;
        loop {
            //if line_offsets[y_count as usize] <= x_count as i32 {
            //    break;
            //}

            

            println!("y_count == {}", y_count);
            if y_count as usize == line_offsets.len() || !(line_offsets[y_count as usize] <= x_count as i32 && line_offsets[y_count as usize] + (out_map[y_count as usize].len() - 1) as i32 >= x_count as i32) {
                break;
            }

            println!("poopoo {}", (line_offsets[y_count as usize] <= x_count as i32 && line_offsets[y_count as usize] + (out_map[y_count as usize].len() - 1) as i32 >= x_count as i32));
            y_count += 1;
        }

        horizontal_lengths.push(y_count - intermediate);


    }

    //println!("horizontal_lengths: {}", horizontal_lengths);

    println!("horizontal_lengths: {:?}", horizontal_lengths);
    
    //println!("horizontal_offsets: {}", horizontal_offsets);

    println!("horizontal_offsets: {:?}", horizontal_offsets);


    //(out_map, line_offsets, moves, move_lenghts);

    (out_map, line_offsets, moves, move_lenghts, horizontal_offsets, horizontal_lengths)

}



fn main_loop(game_map: Vec<Vec<i32>>, line_offsets: Vec<i32>, mut moves: Vec<i32>, move_lenghts: Vec<i32>, vertical_offsets: Vec<i32>, vertical_lengths: Vec<i32>) -> i32 {

    let mut cur_x: i32 = line_offsets[0]; // This must be here because we start on the top.
    let mut cur_y: i32 = 0;

    let mut distance: i32 = 0;

    let mut turn = 0;

    let mut facing = 0;  // "Facing is 0 for right (>), 1 for down (v), 2 for left (<), and 3 for up (^)."

    let mut counter = 0;

    let mut dx = 0;

    let mut dy = 0;

    let mut x_access = 0;

    let mut y_access = 0;

    let mut prev_x = 0;

    let mut prev_y = 0;

    moves.push(1); // final move does not matter

    for m in moves {

        // Mainloop

        distance = move_lenghts[counter];

        // Try to go forward
        println!("facing == {}", facing);
        match facing {
            0 => {
                dx = 1;
                dy = 0;
            }
            1 => {
                dx = 0;
                dy = 1;  // Y is one on the highest level and the biggest on the ground.
            }
            2 => {
                dx = -1;
                dy = 0;
            }
            3 => {
                dx = 0;
                dy = -1;
            }
            _ => {
                assert!(false); // shouldn't happen.
            }
        }

        // Try to advance
        
        println!("distance == {}", distance);
        for n in 0..distance {



            prev_x = cur_x;

            prev_y = cur_y;

            cur_x += dx;

            cur_y += dy;

            println!("cur_y before check: {}", cur_y);
            println!("cur_x before check: {}", cur_x);

            // check loop.

            // check Y

            /*

            if vertical_offsets[cur_x as usize] > cur_y { // underflow aka go up
                println!("poopoothing1");
                cur_y = (vertical_offsets[cur_x as usize]  as usize + (vertical_lengths[cur_x as usize] as usize) - 1) as i32; // loop back around
            }

            if vertical_offsets[cur_x as usize] + vertical_lengths[cur_x as usize] -1 < cur_y {
                println!("poopoothing2");
                cur_y = (vertical_offsets[cur_x as usize]  as usize) as i32;  // overflow aka go down
            } 

            // check X

            if line_offsets[cur_y as usize] > cur_x {
                cur_x = line_offsets[cur_y as usize]  as i32 + (game_map[cur_y as usize].len() - 1) as i32; // loop to the right when going left
            }

            if line_offsets[cur_y as usize] + (game_map[cur_y as usize].len() as i32) -1 < cur_x {
                cur_x = line_offsets[cur_y as usize]  as i32; // loop to the left when going right
            }

            */

            if vertical_offsets[prev_x as usize] > cur_y { // underflow aka go up
                println!("poopoothing1");
                cur_y = (vertical_offsets[prev_x as usize]  as usize + (vertical_lengths[prev_x as usize] as usize) - 1) as i32; // loop back around
            }

            if vertical_offsets[prev_x as usize] + vertical_lengths[prev_x as usize] -1 < cur_y {
                println!("poopoothing2");
                cur_y = (vertical_offsets[prev_x as usize]  as usize) as i32;  // overflow aka go down
            } 

            // check X

            if line_offsets[prev_y as usize] > cur_x {
                println!("poopoothing3");
                cur_x = line_offsets[prev_y as usize]  as i32 + (game_map[prev_y as usize].len() - 1) as i32; // loop to the right when going left
            }

            if line_offsets[prev_y as usize] + (game_map[prev_y as usize].len() as i32) -1 < cur_x {
                println!("poopoothing4");
                cur_x = line_offsets[prev_y as usize]  as i32; // loop to the left when going right
            }



            println!("line_offsets[cur_y as usize] + (game_map[cur_y as usize].len() as i32) == {}",line_offsets[cur_y as usize] + (game_map[cur_y as usize].len() as i32));

            // check block

            // actual place is cur_x, (line_offsets[cur_y]+cur_x)%game_map[cur_y].len()

            println!("cur_y: {}", cur_y);
            println!("cur_x: {}", cur_x);
            //println!("game_map.len() == {}\n",game_map.len());
            //if game_map[(cur_y as usize % game_map.len()) as usize][((line_offsets[(cur_y as usize % game_map.len()) as usize]+cur_x)%(game_map[(cur_y as usize % game_map.len()) as usize].len()) as i32) as usize] == 1 {

            //x_access = ((line_offsets[(cur_y as usize % game_map.len()) as usize]+cur_x)%(game_map[(cur_y as usize % game_map.len()) as usize].len()) as i32) as usize;
            
            //y_access = (cur_y as usize % game_map.len()) as usize
            
            //println!("(vertical_offsets[(cur_x as usize % game_map[cur_y as usize].len()) as usize]+cur_y) == {}",(vertical_offsets[(cur_x as usize % game_map[cur_y as usize].len()) as usize]+cur_y));

            //println!("(game_map[(cur_x as usize % game_map[cur_y as usize].len()) as usize].len()) == {}", (game_map[(cur_x as usize % game_map[cur_y as usize].len()) as usize].len()));
            // y_access = (offset)+(y%vertical_length)


            //y_access = ((vertical_offsets[(cur_x as usize % game_map[cur_y as usize].len()) as usize]+cur_y)%(game_map[(cur_x as usize % game_map[cur_y as usize].len()) as usize].len()) as i32) as usize;
            
            //y_access = (vertical_offsets[cur_x as usize % vertical_offsets.len()]) + (cur_y % horizontal_lengths[cur_x as usize % vertical_offsets.len()]);


            //println!("access index: {}",cur_x as usize % vertical_offsets.len());
            
            //println!("current vertical offset: {}", vertical_offsets[cur_x as usize % vertical_offsets.len()]);
            //println!("current vertical length: {}",vertical_lengths[cur_x as usize % vertical_offsets.len()]);
            
            //y_access = (vertical_offsets[cur_x as usize % vertical_offsets.len()]) as usize + (cur_y as usize % vertical_lengths[cur_x as usize % vertical_offsets.len()] as usize) as usize;


            //println!("x_access: {}", x_access);
            //println!("y_access: {}", y_access);

            x_access = cur_x - line_offsets[cur_y as usize]; // delete the offset.

            //y_access = cur_y - vertical_offsets[cur_x as usize];

            y_access = cur_y;

            println!("x_access: {}", x_access);
            println!("y_access: {}", y_access);
            println!("game_map[y_access as usize][x_access as usize] == {}",game_map[y_access as usize][x_access as usize]);
            if game_map[y_access as usize][x_access as usize] == 1 {
                // Blocked
                println!("Blocked");
                //cur_y -= dy;

                //cur_x -= dx;

                cur_x = prev_x;
                cur_y = prev_y;

                println!("cur_y: {}", cur_y);
                println!("cur_x: {}", cur_x);

                break


            }

        
        }

        if m == 0 {
            println!("Decrementing facing.");
            println!("Facing before decrement: {}", facing);

            facing -= 1; // left
            println!("Facing after decrement: {}", facing);
            // The precent sign works differently than in python. In python it is the modulo, when as in rust it is the remainder. The modulo and the remainder are the same for non-negative divisors and dividends, but for negative numbers they differ: https://stackoverflow.com/questions/31210357/is-there-a-modulus-not-remainder-function-operation
            // for example -2 % 5 = -2   , but (-2).rem_euclid(5) = 3




            //facing = facing % 4;
            facing = (facing as i32).rem_euclid(4);
            println!("Facing after modulo: {}", facing);
        } else {
            // assume right
            facing += 1;
            facing = (facing as i32).rem_euclid(4);
            //facing = facing % 4;
        }



        
        counter += 1;



    }
    facing -= 1; // reset the facing because we add one on the last cycle
    

    // Need to add one because the coordinates are one base index based

    cur_x += 1;
    cur_y += 1;

    println!("Final x: {}\n", cur_x);
    println!("Final y: {}\n", cur_y);

    let password: i32 = cur_y * 1000 + cur_x * 4 + facing;

    println!("Password should be: {}", password);

    return password;


}



fn main() {
    
    //let (game_map: Vec<i32>, line_offsets: Vec<i32>, moves: Vec<i32>, move_lenghts: Vec<i32>) = parse_input();

    //let (game_map, line_offsets, moves, move_lenghts) = parse_input();
    let (game_map, line_offsets, moves, move_lenghts, horizontal_offsets, horizontal_lengths) = parse_input();
    let mut answer: i32;

    answer = main_loop(game_map, line_offsets, moves, move_lenghts, horizontal_offsets, horizontal_lengths);

    println!("[+] Puzzle solution is: {}", answer);

    return ()
}



```
{% endraw %}


It is quite ugly, but for my basically first ever rust program it does not seem that bad.


## Part 2

I thought that the map was shaped in a bit of a weird way. As it turns out the distinct "blocks" are actually the sides of a cuboid (rectangle but in 3d). Now instead of wrapping around the map we wrap around this "cuboid".

Lets implement a "wrap around" function which determines the coordinates after moving.


First step is to identify the distinct sides of the cuboid. As it turns out, the shape is actually a cube, which is the special case of the cuboid where all of the sides are of the same shape.

Second step is to determine the coordinates on the map where each of the cubes sides are.

Third step is to implement the teleport function which takes the coordinates and the direction where we are moving to and outputs the coordinates where we "teleport" .

-------

As it turns out this problem is really difficult for me. I don't really know how to implement the function which identifies the distinct sides of the cube.

Ok so I think that I figured out how to "walk" accross the map and check which coordinates correspond to which side. I still do not understand how I can know the "orientation" of the sides.

See, we know the moves which lead to a certain side.

Yeah this turned out to be really difficult. I am gonna put this on the back burner for now.




























