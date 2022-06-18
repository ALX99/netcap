SRC=$(wildcard *.c)

build: $(SRC)
	gcc $^ -o netcap
