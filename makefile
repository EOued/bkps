CFILES = \
	main.c\
	key_manager.c\

SRCDIR = src
SOURCES = $(foreach file, $(CFILES), $(SRCDIR)/$(file))
OBJDIR = build/obj
INCLUDE = -I$(SRCDIR)/headers
OFILES = $(CFILES:.c=.o)
SUBDIRS = 
TARGETS = $(foreach file, $(OFILES), $(OBJDIR)/$(file))
EXECDIR = build/target
EXECNAME = bkps
EXEC = $(EXECDIR)/$(EXECNAME)
GXX = gcc
FLAGS=-g -Wall -Wextra -Wvla -pedantic -fsanitize=address,undefined
POSTFLAGS=-lm -lsodium

# ============== DO NOT EDIT =============


debug=0
ifeq ($(debug),1)
FLAGS += -DDEBUG
else
FLAGS += -Werror
endif

test = 0
ifeq ($(test),1)
FLAGS += -DTEST
endif


$(shell mkdir -p $(OBJDIR))
$(shell mkdir -p $(EXECDIR))
$(foreach dir, $(SUBDIRS), $(shell mkdir -p $(OBJDIR)/$(dir)))

# The final target depends on all object files
# Rule to generate object files from source files

$(EXEC): $(TARGETS)
	$(GXX) $(FLAGS) $(INCLUDE) -o $(EXEC) $(TARGETS) $(POSTFLAGS)

$(SRCDIR)/parser/ics.c: $(SRCDIR)/parser/ics.lex
	lex -o $(SRCDIR)/parser/ics.c --header-file=$(SRCDIR)/headers/ics.h $(SRCDIR)/parser/ics.lex


$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(GXX) $(FLAGS) $(INCLUDE) -c $< -o $@ $(POSTFLAGS)





# Clean rule
clean:
	rm -rf $(EXEC) $(OBJDIR);


