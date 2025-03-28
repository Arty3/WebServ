# **************************************************************************** #

TARGET		:= webserv

SHELL		:= /bin/sh

# Check platform (must be linux)
OS			:= $(shell uname -s | tr -d '[:space:]')

ifneq ($(OS),Linux)
$(error This program is only meant to be used on Linux systems)
endif

# Alias to default C++ compiler
CXX			:= c++

# Get the full path of the compiler binary
COMPILER_PATH := $(shell which $(CXX))
COMPILER_REAL := $(shell readlink -f $(COMPILER_PATH))

# Check if it's g++ or clang++
COMPILER_TYPE := $(shell $(COMPILER_REAL) --version 2>&1 | grep -E '(clang|g\+\+)' | wc -l)

ifeq ($(COMPILER_TYPE),0)
$(error Compiler must be either g++ or clang++, \
but detected: $(shell $(CXX) --version | head -n1))
endif

# Important for some features
CXXSTD		:= -std=c++20

# Agressive is fine since no IEE float
# stuff or precise loop stuff is needed.
# For debug build, use CXXDEBUG instead.
CXXOPT		:= -Ofast

CXXFLAGS	:=	-Wall -Wextra -Werror -fpermissive -fno-common		\
				-Wpedantic -fstack-protector-strong	-Wconversion	\
				-Wshadow -Wcast-align -Wunused -Wold-style-cast		\
				-Wpointer-arith -Wcast-qual -Wno-missing-braces		\
				-D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS -D__LINUX_BUILD

CXXDEBUG	:=	-g3 -O0

SRC			:=	src/main.cpp								\
				src/server/Server.cpp						\
				src/configuration/ServerConfiguration.cpp	\
				src/configuration/Parse.cpp					\
				src/http/HttpRequest.cpp					\
				src/http/HttpResponse.cpp					\
				src/server/RequestManager.cpp				\
				src/configuration/Route.cpp					\
				src/cgi/CGIHandler.cpp						\
				src/utils/read_file.cpp						\
				src/utils/signal_handler.cpp

HEADERS		:=	include/server/Server.hpp						\
				include/configuration/ServerConfiguration.hpp	\
				include/configuration/Parse.hpp					\
				include/http/HttpMethod.hpp						\
				include/http/HttpStatusCode.hpp					\
				include/http/HttpRequest.hpp					\
				include/http/HttpResponse.hpp					\
				include/server/RequestManager.hpp				\
				include/configuration/Route.hpp					\
				include/cgi/CGIHandler.hpp						\
				include/utils/utils.hpp

BIN_DIR		:= bin
OBJ_DIR		:= obj
DOBJ_DIR	:= debug_obj
OBJ			= $(SRC:%.cpp=$(OBJ_DIR)/%.o)
DOBJ		= $(SRC:%.cpp=$(DOBJ_DIR)/%.o)

all:
	@echo "\033[92mCompiling release build...\n\033[0m"
	@start_time=$$(date +%s);					\
	make actual_build;							\
	end_time=$$(date +%s);						\
	elapsed_time=$$((end_time - start_time));	\
	echo "\n\033[96mBuild completed in $$elapsed_time seconds.\033[0m"
	@echo "\033[92mSuccessfully compiled release build.\033[0m\n"

debug:
	@echo "\033[92mCompiling debug build...\n\033[0m"
	@start_time=$$(date +%s);					\
	make actual_debug_build;					\
	end_time=$$(date +%s);						\
	elapsed_time=$$((end_time - start_time));	\
	echo "\n\033[96mBuild completed in $$elapsed_time seconds.\033[0m"
	@echo "\033[92mSuccessfully compiled debug build.\033[0m\n"

actual_build:		$(BIN_DIR)/$(TARGET)
actual_debug_build:	$(BIN_DIR)/$(TARGET)_debug

$(BIN_DIR)/$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CXX) $(OBJ) -o $@

$(BIN_DIR)/$(TARGET)_debug: $(DOBJ) | $(BIN_DIR)
	$(CXX) $(DOBJ) -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR)/%.o: %.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXSTD) $(CXXOPT) $(CXXFLAGS)	\
	-Iinclude -c $< -o $@

$(DOBJ_DIR)/%.o: %.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXSTD) $(CXXDEBUG) $(CXXFLAGS)	\
	-Iinclude -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(DOBJ_DIR)
	@echo "\n\033[33mSuccessfully cleaned build\033[0m\n"

fclean: clean
	rm -rf $(BIN_DIR)
	@echo "\n\033[38;5;208mSuccessfully deleted build\033[0m\n"

re: fclean all

.SUFFIXES: .cpp .hpp .o
.NOTPARALLEL: fclean clean
.PHONY: all debug actual_build actual_debug_build clean fclean re
