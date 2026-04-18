CFILES = \
	key_manager.c\
	encryption.c\

SRCDIR = src
OBJDIR = build/obj
SUBDIRS =
INCLUDE = -I$(SRCDIR)/headers
EXECDIR = build/target
EXECNAME = bkps
MAINFILE = main.c
TESTFILE = tests.c
GXX = gcc
FLAGS=-g -Wall -Wextra -Wvla -pedantic -fsanitize=address,undefined
POSTFLAGS=-lm -lsodium 


SOURCES = $(foreach file, $(CFILES), $(SRCDIR)/$(file))
OFILES = $(CFILES:.c=.o)
TARGETS = $(foreach file, $(OFILES), $(OBJDIR)/$(file))
MAINFILE_TARGET = $(OBJDIR)/$(MAINFILE:.c=.o)
MAIN_TARGETS = $(TARGETS)
MAIN_TARGETS += $(MAINFILE_TARGET)
TESTFILE_TARGET = $(OBJDIR)/$(TESTFILE:.c=.o)
TEST_TARGETS = $(TARGETS)
TEST_TARGETS += $(TESTFILE_TARGET)
EXEC = $(EXECDIR)/$(EXECNAME)




# ============== DO NOT EDIT =============


debug=0
ifeq ($(debug),1)
FLAGS += -DDEBUG
else
FLAGS += -Werror
endif


$(shell mkdir -p $(OBJDIR))
$(shell mkdir -p $(EXECDIR))
$(foreach dir, $(SUBDIRS), $(shell mkdir -p $(OBJDIR)/$(dir)))

# The final target depends on all object files
# Rule to generate object files from source files

$(EXEC): $(MAIN_TARGETS)
	$(GXX) $(FLAGS) $(INCLUDE) -o $(EXEC) $(MAIN_TARGETS) $(POSTFLAGS)

test: $(TEST_TARGETS)
	$(GXX) $(FLAGS) $(INCLUDE) -o $(EXEC) $(TEST_TARGETS) $(POSTFLAGS) -lcriterion

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(GXX) $(FLAGS) $(INCLUDE) -c $< -o $@ $(POSTFLAGS)

# Clean rule
clean:
	rm -rf $(EXEC) $(OBJDIR);


