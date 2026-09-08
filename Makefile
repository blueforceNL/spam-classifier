CC        := g++
LD        := g++
CFLAGS    := -Wall -O3

MODULES   := heuristic scam_generic advertisement
SRC_DIR   := src $(addprefix src/modules/,$(MODULES))
BUILD_DIR := bin $(addprefix bin/modules/,$(MODULES))

SRC       := $(foreach sdir,$(SRC_DIR),$(wildcard $(sdir)/*.cpp))
OBJ       := $(patsubst src/%.cpp,bin/%.o,$(SRC))
INCLUDES  := $(addprefix -I,$(SRC_DIR)) -I"include"

vpath %.cpp $(SRC_DIR)

define make-goal
$1/%.o: %.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $$< -o $$@
endef

.PHONY: all checkdirs clean

all: checkdirs bin/spam-classifier

bin/spam-classifier: $(OBJ)
	$(LD) $^ -o $@

checkdirs: $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $@
clean:
	rm -rf $(BUILD_DIR)

$(foreach bdir,$(BUILD_DIR),$(eval $(call make-goal,$(bdir))))
