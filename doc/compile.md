# Compilation Instructions

A Makefile is provided for compilation.

To compile the source code, simply run `make`. By default, the Makefile will
compile all of the `.java` files within the `src/` directory and output the
resulting `.class` files within the `build/` directory, which it will create if
none exists. You may optionally override the output directory by specifying the
`OUTPUT_DIR` environment variable. For example, `make OUTPUT_DIR=/path/to/output`.

**Note**: the Makefile expects all required JAR dependencies that are not
already on the Java class path to be located in a directory named `lib/`, though
you may optionally override this at the command line by specifying the `CP`
environment variable. For example, `make CP=/path/to/JAR`.

The Makefile also provides a rule, `make clean`, which will remove any compiled
Java class files for you.
