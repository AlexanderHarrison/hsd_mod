#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdalign.h>
#include <string.h>
#include <stdio.h>

#include "dat.h"

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
    Symbol root_name;
    uint32_t offset_count;
    ObjOffset *offsets;
    ExprType expr_type;
    uint32_t expr;
    Symbol expr_type_symbol;
    Symbol expr_symbol;

    Symbol instr_symbol;
    Instr *next;
};

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

void take_whitespace(char **file, char *end) {
    if (*file >= end) return;
    while (is_whitespace(file)) {
        (*file)++;
        if (*file >= end) return;
    }
}

Symbol take_string(char **file, char *end) {
    Symbol err = { NULL, 0 };

    take_whitespace(file, end);
    if (*file >= end) return err;
    
    char *string_start = *file;
    if (!is_string_start(file))
        return err;

    do {
        (*file)++;
    } while (*file < end && is_string_continue(file));

    return (Symbol) { string_start, (size_t)(*file - string_start) };
}

// returns less than -1 on error
int64_t take_number_unsigned(char **file, char *end) {
    take_whitespace(file, end);
    if (*file >= end) return -1;

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
                n = n * 16 + (uint32_t)(c - 'f');
            else if ('A' <= c && c <= 'F')
                n = n * 16 + (uint32_t)(c - 'F');
            else
                return (int64_t)n;

            (*file)++;
        }
    } else {
        while (*file < end) {
            char c = **file;
            if (is_numeric(file))
                n = n * 10 + (uint32_t)(c - '0');
            else
                return (int64_t)n;

            (*file)++;
        }
    }

    return n;
}

int64_t take_expr_type(char **file, char *end) {
    take_whitespace(file, end);

    if (*file >= end) return -1;

    char c = **file;
    if (c == 'u') {
        (*file)++;
        if (*file >= end) return -1;

        if (**file == '8') {
            (*file)++;
            return ExprType_u8;
        } else if (*file + 1 < end && **file == '1' && *(*file+1) == '6') {
            *file += 2;
            return ExprType_u16;
        } else if (*file + 1 < end && **file == '3' && *(*file+1) == '2') {
            *file += 2;
            return ExprType_u32;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

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

Instr *parse(Arena *arena, char *file, char *file_end) {
    Instr *first_instr = NULL;
    Instr *next_instr = NULL;

    bool found_err = false;

    while (1) {
        take_whitespace(&file, file_end);
        if (file >= file_end) break;

        char *instr_start = file;

        Symbol root_name = take_string(&file, file_end);
        if (root_name.ptr == NULL) {
            found_err = true;
            parse_err(file, "root string");
            goto TAKE_UNTIL_SEMICOLON;
        }

        uint32_t offset_count = 0;
        ObjOffset *offsets = arena_align(arena, alignof(*offsets));

        while (1) {
            take_whitespace(&file, file_end);

            if (file >= file_end) {
                found_err = true;
                parse_err(file, "'.' or '='");
                goto TAKE_UNTIL_SEMICOLON;
            }

            char c = *file;
            if (c == '.') {
                file++;
                char *obj_offset_start = file;
                int64_t num = take_number_unsigned(&file, file_end);
                if (num < 0) {
                    found_err = true;
                    parse_err(file, "unsigned number");
                    goto TAKE_UNTIL_SEMICOLON;
                }
                offset_count++;
                ObjOffset *offset = arena_alloc(arena, sizeof(*offset), alignof(*offset));
                *offset = (ObjOffset) {
                    (uint32_t)num,
                    (Symbol) { obj_offset_start, (size_t)(file - obj_offset_start) }
                };
            } else if (c == '=') {
                if (offset_count == 0) {
                    found_err = true;
                    parse_err(file, "'.'");
                    goto TAKE_UNTIL_SEMICOLON;
                }

                file++;
                break;
            } else {
                found_err = true;
                parse_err(file, "'.' or '='");
                goto TAKE_UNTIL_SEMICOLON;
            }
        }

        char *expr_type_start = file;
        int64_t expr_ret = take_expr_type(&file, file_end);
        if (expr_ret < 0) {
            found_err = true;
            parse_err(file, "type");
            goto TAKE_UNTIL_SEMICOLON;
        }
        ExprType expr_type = (ExprType) expr_ret;
        Symbol expr_type_symbol = (Symbol) { expr_type_start, (size_t)(file - expr_type_start) };

        char *expr_start = file;
        expr_ret = take_number_unsigned(&file, file_end);
        if (expr_ret < 0) {
            found_err = true;
            parse_err(file, "expr");
            goto TAKE_UNTIL_SEMICOLON;
        }
        uint32_t expr = (uint32_t)expr_ret;
        Symbol expr_symbol = (Symbol) { expr_start, (size_t)(file - expr_start) };

        Instr *instr = arena_alloc(arena, sizeof(Instr), alignof(Instr));
        if (first_instr == NULL)
            first_instr = instr;

        if (next_instr != NULL) 
            next_instr->next = instr;
        next_instr = instr;

        while (file < file_end && *file != ';')
            file++;

        Symbol instr_symbol = (Symbol) { instr_start, (size_t)(file - instr_start) };

        *instr = (Instr) {
            root_name, offset_count, offsets, expr_type, expr,
            expr_type_symbol, expr_symbol, instr_symbol,
            NULL
        };

TAKE_UNTIL_SEMICOLON:
        while (file < file_end && *file != ';')
            file++;
        file++;
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

bool dat_follow_ref(DatFile *dat, DatRef *obj, uint32_t offset) {
    DatRef ref = *obj + offset;
    if (ref > dat->data_size) return true;
    if ((ref & 3) != 0) return true;
    *obj = READ_U32(dat->data + *obj + offset);

    if (*obj >= dat->data_size) return true;
    return false;
}

// returns < 0 if err
bool apply_instr(DatFile *dat, Instr *instr) {
    // find offset -----------------------------------------------------------

    DatRef obj = 0;

    for (uint32_t i = 0; i < dat->root_count; ++i) {
        DatRootInfo root_info = dat->root_info[i];
        char *root_symbol = dat->symbols + root_info.symbol_offset;
        Symbol target_symbol = instr->root_name;

        bool found = true;
        for (size_t j = 0; j < target_symbol.size; ++j) {
            if (root_symbol[j] == '0' || root_symbol[j] != target_symbol.ptr[j]) {
                found = false;
                break;
            }
        }

        if (found) {
            obj = root_info.data_offset;
            break;
        }
    }

    if (obj == 0) {
        dat_print_err_header(dat, instr);
        fprintf(stderr, "Root '%.*s' not found", (int)instr->root_name.size, instr->root_name.ptr);
        dat_print_err_trailer(dat, instr, &instr->root_name);
        return true;
    }

    for (size_t i = 0; i+1 < instr->offset_count; ++i) {
        ObjOffset *obj_offset = &instr->offsets[i];
        if (dat_follow_ref(dat, &obj, obj_offset->offset)) {
            dat_print_err_header(dat, instr);
            fprintf(
                stderr,
                "Pointer at offset '%.*s' (0x%x) is invalid",
                (int)obj_offset->symbol.size,
                obj_offset->symbol.ptr,
                obj+obj_offset->offset
            );
            dat_print_err_trailer(dat, instr, &obj_offset->symbol);

            return true;
        }
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
        fprintf(stderr, "Offset '%.*s' has invalid alignment", (int)obj_offset->symbol.size, obj_offset->symbol.ptr);
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
