#!/bin/bash

# Const
BASENAME=$(basename $0)

FILE_UNSUPPORTED_SYMBOLS="$(dirname $0)/symbols/unsupported"
FILE_PRESENT_BUT_UNSUPPORTED="$(dirname $0)/symbols/present_but_unsupported"
SEARCH_DEPTH=3

print_usage() {
    echo "Usage: $BASENAME <docker_image> <appdir> [executable]"
    echo "  where <docker_image> should be name of a Docker image"
    echo "  where <appdir> should point to appdir generated from the Docker image"
    echo "  where [executable] is an optional path to an executable inside appdir"
    echo "    The executable should be the starting point of your application"
    echo "    The path should be absolute (imagine appdir is the root)"
    echo "    If specified, this will override the executable specified in Dockerfile's ENTRYPOINT"
    echo ""
    echo "  For more details see scripts/symbol_check/readme.md"
}

print_warning_unsupported() {
    local unsupported_symbols=$1
    local executable=$2

    unique_symbols=$(echo "$unsupported_symbols" | tr ' ' '\n' | sort | uniq)
    counts=$(echo "$unique_symbols" | wc -w)

    echo "Warning: $counts unsupported symbol(s) found in $executable"
    echo "  Your application or its interpreter is using symbols not yet supported in Mystikos,"
    echo "  which may cause your program to exit if they are used."
    echo "  If you encounter error when running your application because of it,"
    echo "  please submit an issue here: https://github.com/deislabs/mystikos/issues/new"
    echo "  and include the list of symbols below:"

    # print each symbol in a new line
    echo ">>> unsupported symbol(s)"
    echo "$unique_symbols" | tr ' ' '\n'
    echo "<<<"
}

# Possible input format:
# 1. symbol_name
# 2. symbol_name@@GLIBC_x.y.z
# Output should be: symbols_name
parse_symbol() {
    echo $(echo $1 | cut -d'@' -f 1)
}

# Given a Docker image name
# Return the ENTRYPOINT command in that image
parse_entrypoint() {
    local image_name=$1

    entrypoint=$(docker image inspect --format='{{json .Config.Entrypoint}}' $image_name)
    # get string between double-quotaion mark
    # exmaple: "something" -> something
    args=$(echo $entrypoint | grep -o '"[^"]*"')

    # ENTRYPOINT cannot be empty/null
    if [[ "null" == $entrypoint ]] || [[ -z $args || ${#args[@]} -eq 0 ]]; then
        echo "Skipping symbol check: Failed to find ENTRYPOINT for Docker image $image_name" >&2
        return 1
    fi

    executable=($args)
    executable=${executable[0]:1:-1}

    # check if path absolute
    if [[ ! "$executable" =~ ^/.* ]]; then
        echo "Skipping symbol check: ENTRYPOINT must be absolute. Instead got: $executable" >&2
        exit 1
    fi

    echo $executable
}

# Given a executable/shared object
# Return a list of UNDEFINED symbols that it uses
get_list_symbols() {
    local executable=$1

    # List dynamic external Undefined symbols, filter only undefined symbols
    raw_symbols=$(nm -D -g -u $executable 2>/dev/null | grep " U "); rc=${PIPESTATUS[0]}
    if [[ $rc -ne 0 ]]; then
        # Skip this shared object
        echo "get_list_symbols: Failed to read symbols from $executable" >&2
        return 1
    fi

    parsed_symbols=""
    for line in ${raw_symbols}; do
        if [[ "U" != $line ]]; then
            parsed_symbols+="$(parse_symbol $line) "
        fi
    done

    echo "${parsed_symbols}"
}

# Given an executable, return a list of shared objects used by it and its dependencies
get_list_shared_objects() {
    local appdir=$1
    # Note: The path of executable should be relative to appdir
    local executable=$2

    # This list stores all shared objects used by the executable and its dependencies
    # All paths should be relative to appdir
    list_shared_objects="$executable"

    # A queue used for BFS
    queue="$executable"

    # Current search depth
    level=0
    while [[ ! -z "$queue" && $level -lt $SEARCH_DEPTH ]]; do
        # For each shared object in the queue, list its dependencies
        # And add them to the queue
        queue_next_level=""
        for object in $queue; do
            # Use ldd to list all linked .so, grab lines contain "=>" but not "not found"
            output="$(ldd $appdir$object 2>/dev/null | grep "=>" | grep -i -v "not" | cut -d' ' -f 3)"; rc=${PIPESTATUS[0]}
            if [[ $rc -eq 0 ]]; then
                queue_next_level+="$output "
            fi
        done

        list_shared_objects=$(echo "$list_shared_objects $queue_next_level" | tr ' ' '\n' | sort | uniq)
        queue=$queue_next_level

        # increase level
        level=$((level+1))
    done

    echo "${list_shared_objects}"
}

# Given an executable
# Return a list of symbols used by the executable and its dependencies
get_list_symbols_of_executable() {
    local appdir=$1
    local executable=$2
    # 1. find all lib dependencies using ldd
    list_so=$(get_list_shared_objects "$appdir" "$executable")

    # 2. check symbols of each dependency using nm
    list_symbols=""

    for each in $list_so; do
        tmp_symbols="$(get_list_symbols $appdir$each) "; rc=${PIPESTATUS[0]}
        if [[ $rc -eq 0 ]]; then
            list_symbols=$(echo "$list_symbols $tmp_symbols" | tr ' ' '\n' | sort | uniq)
        fi
    done

    echo "$list_symbols"
}

# Given a list of symbols(string) and a file
# Return only symbols that are present in the given file
filter_symbols() {
    # List of symbols
    local symbols=$1
    # Path to a file containing symbols, one symbol per line
    local file_symbols=$2

    found_symbols=
    for each in $symbols; do
        if grep -q -w $each "$file_symbols"; then
            found_symbols+="$each "
        fi
    done

    echo "$found_symbols"
}

# Program parameter
image_name=$1
# No need to append "/" to the end of appdir
# Because executable will begin with "/"
appdir=$2
path_executable=$3

if [[ -z $image_name ]] || [[ -z $appdir ]]; then
    print_usage
    exit 0
fi

if [[ -n "$path_executable" ]]; then
    executable="$path_executable"
else
    # Get executable from Docker image
    executable=$(parse_entrypoint $image_name $appdir)
    if [[ $? -eq 1 ]]; then
        exit 0
    fi
fi

# List undefine symbols used in the executable
undefined_symbols=$(get_list_symbols_of_executable $appdir $executable)
if [[ $? -eq 1 ]]; then
    exit 0
fi

# Get symbols that are not supported in Mystikos
missing_symbols=$(filter_symbols "$undefined_symbols" $FILE_UNSUPPORTED_SYMBOLS)
present_but_unsupported_symbols=$(filter_symbols "$undefined_symbols" $FILE_PRESENT_BUT_UNSUPPORTED)

# Combine two lists
unsupported_symbols=$(echo "$missing_symbols $present_but_unsupported_symbols" | tr ' ' '\n' | sort | uniq | grep "\S")

executable_prefixed="$(basename $appdir)$executable"
if [[ -z $unsupported_symbols ]]; then
    echo "0 unsupported symbol found for $executable_prefixed"
else
    print_warning_unsupported "$unsupported_symbols" "$executable_prefixed"
fi

# Program should exit 0 so it doesn't fail the build
exit 0
