#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdalign.h>
#include <string.h>
#include <stdio.h>

#include "dat.h"

#if 0
#  define PARSE_TRACE printf("%s\n", __FUNCTION__);
#else
#  define PARSE_TRACE
#endif

typedef struct File File;
struct File {
    char *ptr;
    size_t size;
};

const char *input_path = NULL;
const char *dat_path = NULL;
const char *dat_out_path = NULL;

File input_file;
File dat_file;

// ARENA ###########################################################################

typedef struct Arena Arena;
struct Arena {
    uint8_t *base;
    uint8_t *head;
    uint8_t *max;
};

Arena arena_create(size_t size) {
    uint8_t *base = malloc(size);
    return (Arena) { base, base, base + size };
}

void arena_destroy(Arena *arena) {
    free(arena->base);
}

void *arena_align(Arena *arena, size_t align) {
    uint8_t *aligned = (uint8_t*)(((size_t)arena->head + align - 1) & ~(align - 1));
    if (aligned > arena->max) return NULL;
    arena->head = aligned;
    return aligned;
}

void *arena_alloc(Arena *arena, size_t size, size_t align) {
    uint8_t *aligned = arena_align(arena, align);
    if (aligned == NULL) return NULL;
    uint8_t *new_head = aligned + size;
    if (new_head > arena->max) return NULL;
    arena->head = new_head;
    return aligned;
}

// PARSING ########################################################################

typedef struct Symbol Symbol;
struct Symbol {
    char *ptr;
    size_t size;
};

char *symbol_end(Symbol *sym) {
    return sym->ptr + sym->size;
}

Symbol symbol_finish(char *start, char **file) {
    return (Symbol) { start, (size_t)(*file - start) };
}

typedef enum ExprType {
    ExprType_u8 = 3,
    ExprType_u16,
    ExprType_u32,
} ExprType;

typedef struct ObjOffset ObjOffset;
struct ObjOffset {
    uint32_t offset;
    Symbol symbol;
};

typedef struct Instr Instr;
struct Instr {
    Symbol root_symbol;
    uint32_t offset_count;
    ObjOffset *offsets;
    ExprType expr_type;
    uint32_t expr;
    Symbol expr_type_symbol;
    Symbol expr_symbol;

    Symbol instr_symbol;
    Instr *next;
};

#define RED "\033[0;31m"
#define BOLD "\033[0;1m"
#define CLEAR "\033[0m"

void print_err_location(char *err_point, char **line_start_out, char **line_end_out) {
    char *line_start = err_point;
    while (line_start > input_file.ptr && *(line_start-1) != '\n')
        line_start--;

    char *line_end = err_point;
    char *end = input_file.ptr + input_file.size;
    while (line_end < end && *line_end != '\n')
        line_end++;

    uint64_t line_count = 1;
    char *line_counter = line_start;
    while (line_counter >= input_file.ptr) {
        if (*line_counter == '\n')
            line_count++;
        line_counter--;
    }

    fprintf(
        stderr,
        BOLD "%s:%lu:%li: " CLEAR,
        input_path,
        line_count, err_point - line_start + 1
    );

    *line_start_out = line_start;
    *line_end_out = line_end;
}

void parse_err(char *err_point, const char *expected) {
    char *line_start, *line_end;
    print_err_location(err_point, &line_start, &line_end);

    int line_before_len = (int)(err_point - line_start);
    int line_after_len = line_end == err_point ? 0 : (int)(line_end - err_point - 1);

    fprintf(
        stderr,
        "Parse error - Expected %s\n%.*s" RED "%c" CLEAR "%.*s\n",
        expected,
        line_before_len, line_start,
        *err_point,
        line_after_len, err_point + 1
    );
}

bool is_whitespace(char **file) {
    char c = **file;
    return c == ' ' || c == '\n' || c == '\t';
}

bool is_alphabetic(char **file) {
    char c = **file;
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

bool is_numeric(char **file) {
    char c = **file;
    return '0' <= c && c <= '9';
}

bool is_underscore(char **file) {
    return **file == '_';
}

bool is_string_start(char **file) {
    return is_alphabetic(file) || is_underscore(file);
}

bool is_string_continue(char **file) {
    return is_alphabetic(file) || is_underscore(file) || is_numeric(file);
}

bool take_whitespace(char **file, char *end) { PARSE_TRACE
    while (1) {
        if (*file >= end)
            return true;
        if (!is_whitespace(file))
            return false;
        (*file)++;
    }
}

bool take_string(char **file, char *end, Symbol *out) { PARSE_TRACE
    if (take_whitespace(file, end))
        return true;
    
    char *string_start = *file;
    if (!is_string_start(file))
        return true;

    do {
        (*file)++;
    } while (*file < end && is_string_continue(file));

    *out = (Symbol) { string_start, (size_t)(*file - string_start) };
    return false;
}

bool take_number_unsigned(char **file, char *end, uint32_t *out) { PARSE_TRACE
    if (take_whitespace(file, end))
        return true;

    bool hex = false;
    if (*file + 2 <= end && **file == '0' && (*(*file+1) == 'x' || *(*file+1) == 'X')) {
        hex = true;
        *file += 2;
    }

    uint32_t n = 0;

    if (hex) {
        while (*file < end) {
            char c = **file;
            if (is_numeric(file))
                n = n * 16 + (uint32_t)(c - '0');
            else if ('a' <= c && c <= 'f')
                n = n * 16 + (uint32_t)(c - 'a');
            else if ('A' <= c && c <= 'F')
                n = n * 16 + (uint32_t)(c - 'A');
            else
                break;

            (*file)++;
        }
    } else {
        while (*file < end) {
            char c = **file;
            if (is_numeric(file))
                n = n * 10 + (uint32_t)(c - '0');
            else
                break;

            (*file)++;
        }
    }

    *out = n;
    return false;
}

bool try_take_keyword(char **file, char *end, const char *keyword) { PARSE_TRACE
    size_t keyword_length = strlen(keyword);

    if (*file + keyword_length > end)
        return true;

    for (size_t i = 0; i < keyword_length; ++i) {
        if (*(*file + i) != keyword[i])
            return true;
    }

    *file += keyword_length;
    return false;
}

bool try_take_char(char **file, char *end, char c) { PARSE_TRACE
    if (*file >= end)
        return true;
    if (**file != c) {
        return true;
    } else {
        (*file)++;
        return false;
    }
}

bool take_expr_type(char **file, char *end, ExprType *out) { PARSE_TRACE
    if (take_whitespace(file, end))
        return true;

    if (!try_take_keyword(file, end, "u8")) {
        *out = ExprType_u8;
    } else if (!try_take_keyword(file, end, "u16")) {
        *out = ExprType_u16;
    } else if (!try_take_keyword(file, end, "u32")) {
        *out = ExprType_u32;
    } else {
        return true;
    }
    return false;
}

bool parse_instr(Arena *arena, char **file, char *end, Instr *instr) { PARSE_TRACE
    instr->next = NULL;

    if (take_whitespace(file, end))
        return true;

    char *instr_symbol_start = *file;

    if (take_string(file, end, &instr->root_symbol)) {
        parse_err(*file, "root string");
        return true;
    }

    instr->offsets = arena_align(arena, alignof(*instr->offsets));
    instr->offset_count = 0;

    // parse offsets
    while (1) {
        if (take_whitespace(file, end)) {
            parse_err(*file, "'.' or '='");
            return true;
        }

        if (!try_take_char(file, end, '.')) {
            char *offset_start = *file;
            uint32_t offset;
            if (take_number_unsigned(file, end, &offset)) {
                parse_err(*file, "unsigned number");
                return true;
            }

            ObjOffset *obj = arena_alloc(arena, sizeof(*obj), alignof(*obj));
            *obj = (ObjOffset) {
                offset,
                symbol_finish(offset_start, file)
            };

            instr->offset_count++;
            continue;
        } else if (!try_take_char(file, end, '=')) {
            break;
        } else {
            parse_err(*file, "'.' or '='");
            return true;
        }
    }

    // parse expr

    char *expr_type_start = *file;
    if (take_expr_type(file, end, &instr->expr_type)) {
        parse_err(*file, "expression type (e.x. 'u8')");
        return true;
    }
    instr->expr_type_symbol = symbol_finish(expr_type_start, file);

    char *expr_start = *file;
    if (take_number_unsigned(file, end, &instr->expr)) {
        parse_err(*file, "expression (e.x. '12' or '0x5')");
        return true;
    }
    instr->expr_symbol = symbol_finish(expr_start, file);
    instr->instr_symbol = symbol_finish(instr_symbol_start, file);

    if (take_whitespace(file, end))
        return true;

    if (try_take_char(file, end, ';'))
        return true;

    return false;
}

Instr *parse(Arena *arena, char *file, char *file_end) { PARSE_TRACE
    Instr *first_instr = NULL;
    Instr *next_instr = NULL;

    bool found_err = false;

    while (1) {
        if (take_whitespace(&file, file_end))
            break;

        if (!try_take_char(&file, file_end, '#'))
            goto TAKE_UNTIL_NEWLINE;

        Instr *instr = arena_alloc(arena, sizeof(Instr), alignof(Instr));
        if (parse_instr(arena, &file, file_end, instr)) {
            found_err = true;
            goto TAKE_UNTIL_SEMICOLON;
        }

        if (first_instr == NULL)
            first_instr = instr;

        if (next_instr != NULL) 
            next_instr->next = instr;
        next_instr = instr;

        continue;

TAKE_UNTIL_SEMICOLON:
        while (file < file_end && *file != ';')
            file++;
        file++;
        continue;

TAKE_UNTIL_NEWLINE:
        while (file < file_end && *file != '\n')
            file++;
        file++;
        continue;
    }

    if (found_err)
        return NULL;

    return first_instr;
}

// EXEC ###########################################################################

void dat_print_err_header(DatFile *dat, Instr *instr) {
    (void)dat;
    char *line_start, *line_end;
    print_err_location(instr->instr_symbol.ptr, &line_start, &line_end);
    fprintf(stderr, "Runtime error - ");
}

void dat_print_err_trailer(DatFile *dat, Instr *instr, Symbol *highlight) {
    (void)dat;
    Symbol instr_symbol = instr->instr_symbol;

    if (highlight == NULL) {
        fprintf(stderr, "\n%.*s\n", (int)instr_symbol.size, instr_symbol.ptr);
    } else {
        int instr_start_size = (int)(highlight->ptr - instr->instr_symbol.ptr);
        int instr_end_size = (int)(symbol_end(&instr->instr_symbol) - symbol_end(highlight));
        fprintf(
            stderr,
            "\n%.*s" RED "%.*s" CLEAR "%.*s\n",
            instr_start_size, instr_symbol.ptr,
            (int)highlight->size, highlight->ptr,
            instr_end_size, symbol_end(highlight)
        );
    }
}

bool dat_follow_ref(DatFile *dat, Instr *instr, DatRef *obj, ObjOffset *obj_offset) {
    const char *err = NULL;
    DatRef ref = *obj + obj_offset->offset;
    DatRef new_obj = 0;

    if (ref > dat->data_size) {
        err = "is out of bounds";
        goto ERR;
    }

    if ((ref & 3) != 0) {
        err = "has invalid alignment";
        goto ERR;
    }

    new_obj = READ_U32(dat->data + *obj + obj_offset->offset);

    if (new_obj >= dat->data_size) {
        err = "points out of bounds";
        goto ERR;
    }

    if ((new_obj & 3) != 0) {
        err = "points to a object with invalid alignment";
        goto ERR;
    }

    if (new_obj == 0) {
        err = "points to null";
        goto ERR;
    }

    *obj = new_obj;
    return false;

ERR:
    dat_print_err_header(dat, instr);
    if (new_obj != 0) {
        fprintf(
            stderr,
            "Pointer at 0x%x + '%.*s' -> 0x%x %s",
            *obj,
            (int)obj_offset->symbol.size, obj_offset->symbol.ptr,
            new_obj,
            err
        );
    } else {
        fprintf(
            stderr,
            "Pointer at 0x%x + '%.*s' %s",
            *obj,
            (int)obj_offset->symbol.size, obj_offset->symbol.ptr,
            err
        );
    }
    dat_print_err_trailer(dat, instr, &obj_offset->symbol);
    return true;
}

// returns < 0 if err
bool apply_instr(DatFile *dat, Instr *instr) {
    // find offset -----------------------------------------------------------

    DatRef obj = UINT32_MAX;

    Symbol target_symbol = instr->root_symbol;
    for (uint32_t i = 0; i < dat->root_count; ++i) {
        DatRootInfo root_info = dat->root_info[i];
        char *root_symbol = dat->symbols + root_info.symbol_offset;

        bool found = true;
        for (size_t j = 0; j < target_symbol.size; ++j) {
            if (root_symbol[j] == 0 || root_symbol[j] != target_symbol.ptr[j]) {
                found = false;
                break;
            }
        }

        if (root_symbol[target_symbol.size] != 0)
            found = false;

        if (found) {
            obj = root_info.data_offset;
            break;
        }
    }

    if (obj == UINT32_MAX) {
        dat_print_err_header(dat, instr);
        fprintf(stderr, "Root '%.*s' not found", (int)instr->root_symbol.size, instr->root_symbol.ptr);
        dat_print_err_trailer(dat, instr, &instr->root_symbol);
        return true;
    }

    for (size_t i = 0; i+1 < instr->offset_count; ++i) {
        ObjOffset *obj_offset = &instr->offsets[i];
        if (dat_follow_ref(dat, instr, &obj, obj_offset))
            return true;
    }
    obj += instr->offsets[instr->offset_count - 1].offset;

    if (obj > dat->data_size) {
        ObjOffset *obj_offset = &instr->offsets[instr->offset_count - 1];

        dat_print_err_header(dat, instr);
        fprintf(
            stderr,
            "Offset '%.*s' (0x%x) is invalid",
            (int)obj_offset->symbol.size,
            obj_offset->symbol.ptr,
            obj
        );
        dat_print_err_trailer(dat, instr, &obj_offset->symbol);
        return true;
    }

    // calculate written bytes -----------------------------------------------------------

    uint8_t bytes[4];
    bytes[0] = (uint8_t)((instr->expr >> 24) & 0xFF);
    bytes[1] = (uint8_t)((instr->expr >> 16) & 0xFF);
    bytes[2] = (uint8_t)((instr->expr >>  8) & 0xFF);
    bytes[3] = (uint8_t)((instr->expr >>  0) & 0xFF);

    size_t bytes_count;
    switch (instr->expr_type) {
        case ExprType_u8:
            bytes_count = 1;
            break;
        case ExprType_u16:
            bytes_count = 2;
            break;
        case ExprType_u32:
            bytes_count = 4;
            break;
    }

    for (size_t i = 0; i < 4 - bytes_count; ++i) {
        if (bytes[i] != 0) {
            dat_print_err_header(dat, instr);
            fprintf(stderr, "Expr '%.*s' is too large", (int)instr->expr_symbol.size, instr->expr_symbol.ptr);
            dat_print_err_trailer(dat, instr, &instr->expr_symbol);
            return true;
        }
    }

    if ((obj & (bytes_count - 1)) != 0) {
        ObjOffset *obj_offset = &instr->offsets[instr->offset_count - 1];

        dat_print_err_header(dat, instr);
        fprintf(stderr, "Offset '%.*s' (0x%x) has invalid alignment", (int)obj_offset->symbol.size, obj_offset->symbol.ptr, obj);
        dat_print_err_trailer(dat, instr, &obj_offset->symbol);
        return true;
    }

    // write! -----------------------------------------------------------

    for (size_t i = 0; i < bytes_count; ++i)
        dat->data[obj + i] = bytes[i + 4 - bytes_count];

    return false;
}

// MAIN ###########################################################################

File read_file(const char* filepath) {
    FILE *f = NULL;
    char *ptr = NULL;

    f = fopen(filepath, "rb");
    if (f == NULL) goto ERR;

    if (fseek(f, 0, SEEK_END) < 0) goto ERR;
    long size_or_err = ftell(f);
    if (size_or_err < 0) goto ERR;
    size_t size = (size_t)size_or_err;
    if (fseek(f, 0, SEEK_SET) < 0) goto ERR;

    ptr = malloc(size);
    if (ptr == NULL) goto ERR;

    if (size != 0 && fread(ptr, size, 1, f) != 1) goto ERR;

    if (fclose(f) != 0) goto ERR;

    return (File) { ptr, size };

ERR:
    if (f) fclose(f);
    if (ptr) free(ptr);
    return (File) { NULL, 0 };
}

bool write_file(const char* filepath, uint8_t *buf, size_t size) {
    FILE *f = NULL;

    f = fopen(filepath, "wb+");
    if (f == NULL) goto ERR;

    if (size != 0 && fwrite(buf, size, 1, f) != 1) goto ERR;
    if (fclose(f) != 0) goto ERR;
    return false;

ERR:
    if (f) fclose(f);
    return true;
}

static const char *HELP = "\
Usage: hsd_mod <dat input path> <dat output path> <input.hsdmod>\n\
\n\
hsdmod File Format:\n\
    any number of lines of form:\n\
    <root string> [. num]*n : <u8 | u16 | u32> = num;\n\
\n\
e.x.:\n\
    coll_data.0x10.0x0.0x6 = 1;\n\
";

int main(int argc, const char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "%s", HELP);
        return 1;
    }

    dat_path = argv[1];
    dat_out_path = argv[2];
    input_path = argv[3];

    dat_file = read_file(dat_path);
    input_file = read_file(input_path);

    if (dat_file.ptr == NULL) {
        fprintf(stderr, "Error: dat file path '%s' not found.\n", dat_path);
        return 1;
    }

    DatFile dat;
    DAT_RET err = dat_file_import((uint8_t*)dat_file.ptr, (uint32_t)(dat_file.size), &dat);
    if (err) {
        fprintf(stderr, "Error: cannot parse dat file '%s': %s\n", dat_path, dat_error_string(err));
        return 1;
    }

    if (input_file.ptr == NULL) {
        fprintf(stderr, "Error: input file path '%s' not found.\n", input_path);
        return 1;
    }

    Arena parse_arena = arena_create(64 * 1024 * 1024);

    Instr *instr = parse(&parse_arena, input_file.ptr, input_file.ptr + input_file.size);

    bool found_err = false;
    while (instr != NULL) {
        found_err |= apply_instr(&dat, instr);
        instr = instr->next;
    }

    if (found_err) {
        fprintf(stderr, "Encountered errors, output dat not written\n");
    } else {
        uint8_t *out_buf = malloc(dat_file_export_max_size(&dat));
        uint32_t dat_size;

        err = dat_file_export(&dat, out_buf, &dat_size);
        if (err != DAT_SUCCESS) {
            fprintf(stderr, "Error: could not create dat file: %s\n", dat_error_string(err));
            return 1;
        }

        if (write_file(dat_out_path, out_buf, dat_size)) {
            fprintf(stderr, "Error: could not write output file '%s'\n", dat_out_path);
            return 1;
        }

        free(out_buf);
    }

    dat_file_destroy(&dat);
    free(dat_file.ptr);
    free(input_file.ptr);
    arena_destroy(&parse_arena);
    return 0;
}
