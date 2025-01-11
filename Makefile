.PHONY: build san test_dat

OUT := hsd_mod
FILES := src/dat.c src/mod.c
BASE_FLAGS := -g -std=c99
SAN_FLAGS := -fsanitize=undefined -fsanitize=address 

WARN_FLAGS := -Wall -Wextra -Wpedantic -Wuninitialized -Wcast-qual -Wdisabled-optimization -Winit-self -Wlogical-op -Wmissing-include-dirs -Wredundant-decls -Wshadow -Wundef -Wstrict-prototypes -Wpointer-to-int-cast -Wint-to-pointer-cast -Wconversion -Wduplicated-cond -Wduplicated-branches -Wformat=2 -Wshift-overflow=2 -Wint-in-bool-context -Wvector-operation-performance -Wvla -Wdisabled-optimization -Wredundant-decls -Wmissing-parameter-type -Wold-style-declaration -Wlogical-not-parentheses -Waddress -Wmemset-transposed-args -Wmemset-elt-size -Wsizeof-pointer-memaccess -Wwrite-strings -Wtrampolines -Werror=implicit-function-declaration

PATH_FLAGS := -I/usr/local/lib -I/usr/local/include
LINK_FLAGS :=

export GCC_COLORS = warning=01;33

build:
	/usr/bin/c99 $(WARN_FLAGS) $(PATH_FLAGS) $(BASE_FLAGS) $(FILES) $(LINK_FLAGS) -o$(OUT)

san:
	/usr/bin/c99 $(WARN_FLAGS) $(PATH_FLAGS) $(SAN_FLAGS) $(BASE_FLAGS) $(FILES) $(LINK_FLAGS) -o$(OUT)

test: san
	/usr/bin/c99 $(WARN_FLAGS) $(PATH_FLAGS) $(SAN_FLAGS) $(BASE_FLAGS) src/dat.c test/test_dat.c $(LINK_FLAGS) -otest_dat
	./test_dat create
	./hsd_mod test.dat test.dat test/test.hsdmod
	./test_dat test

clean:
	rm -r test_dat hsd_mod test.dat
