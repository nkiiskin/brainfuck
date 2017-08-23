Hi folks,

Pbfc is a Brainfuck (BF for short) compiler for Linux.
It compiles x86/AMD64 executable files from Brainfuck source code.
It creates programs/apps only for x86/64 Linux systems.
So, the programs won't in Mac OS, for example.

See http://en.wikipedia.org/wiki/Brainfuck for more information
about the BF language.
----------------------------------------------------------------

-- INSTALLING PBFC:

To install pbfc compiler for Linux system,
you would just type: "make".
Alternatively, you can type "gcc pbfc.c -o pbfc",
the result is the same.
(If you get an error message, it is propably because
 you don't have gcc installed).

Once ready, pbfc compiler should be in the
same directory. you can test the pbfc compiler
using the two sample BF source code files: "hello.bf"
and "99bottles.bf".
(Please note that I am not the author of these files,
they were freely available in the net, so I included them
in this package, so that you can test pbfc without writing
your own BF code).

-- COMPILING Brainfuck source code :

To compile and test -for example- the "hello.bf" program,
type: "./pbfc hello.bf hello"
and then run the compiled program by typing: "./hello"
You should see "Hello World!" appear to the screen.
The second test program "99bottles.bf" does a little
bit more than just write one line, try that too!
(When I tried it, it seemed to be a quite slow but
 slowness is a "feature" of some BF programs.
 Hey, you don't do supercomputer calculations
 using BF language, do you??! :)

Personally I find it funny, that you can give ANY FILE
to pbfc to compile and the resulted program may actually
do something!! Even if the source file is a random text
file, jpg picture, pdf document, or an arbitary binary
file - still the result may run!! Sometimes it may just
output some garbage to the screen, sometimes wait input
from the user, all that -IMHO- adds to the crazyness of
this language. And enjoyment doing such crazy things!


Have fun with pbfc compiler!

  - Niko Kiiskinen

If you have any questions about the pbfc compiler
or if you want to report a bug, my email adderss
is nkiiskin[at]yahoo[dot]com

