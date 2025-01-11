#include <stdio.h>
#include <stdlib.h>

#include "../src/dat.h"

#define assert(A) do{\
        if (A) {} else { fprintf(stderr, "%s:%i: assertion failed\n", __FILE__, __LINE__); exit(1); }\
    }while(0)

#define dat_assert(A) do{\
        DAT_RET __err = A;\
        if (__err != DAT_SUCCESS)\
            fprintf(stderr, "%s:%i: dat error - %s\n", __FILE__, __LINE__, dat_error_string(__err));\
    }while(0)

// root_1 -> obj_1
// root_2 -> obj_2
//
// obj_1:
//  .0 -> obj_3
//  .4 -> obj_4
//
// obj_2:
//  .0 -> obj_3
//  .4 = u32 1000
//
// obj_3:
//  .0 = u16 1
//  .2 = u8 2
//  .3 = u8 3
//  .4 -> obj_4
//
// obj_4:
//  .0 = u32 4

uint32_t read_u32(DatFile *dat, DatRef ref) {
    uint32_t ret;
    dat_assert(dat_obj_read_u32(dat, ref, &ret));
    return ret;
}

uint16_t read_u16(DatFile *dat, DatRef ref) {
    uint16_t ret;
    dat_assert(dat_obj_read_u16(dat, ref, &ret));
    return ret;
}

uint8_t read_u8(DatFile *dat, DatRef ref) {
    uint8_t ret;
    dat_assert(dat_obj_read_u8(dat, ref, &ret));
    return ret;
}

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "no subcommand passed\n");
        return 1;
    }

    if (strcmp(argv[1], "create") == 0) {
        DatFile dat;
        dat_assert(dat_file_new(&dat));
        
        DatRef obj_1, obj_2, obj_3, obj_4;

        dat_assert(dat_obj_alloc(&dat, 8, &obj_1));
        dat_assert(dat_obj_alloc(&dat, 64, &obj_2));
        dat_assert(dat_obj_alloc(&dat, 8, &obj_3));
        dat_assert(dat_obj_alloc(&dat, 32, &obj_4));

        dat_assert(dat_root_add(&dat, dat.root_count, obj_1, "root_1"));
        dat_assert(dat_root_add(&dat, dat.root_count, obj_2, "root_2"));

        dat_assert(dat_obj_set_ref(&dat, obj_1 + 0x0, obj_3));
        dat_assert(dat_obj_set_ref(&dat, obj_1 + 0x4, obj_4));

        dat_assert(dat_obj_set_ref(&dat, obj_2, obj_3));
        dat_assert(dat_obj_write_u32(&dat, obj_2 + 0x4, 1000));

        dat_assert(dat_obj_write_u16(&dat, obj_3, 1));
        dat_assert(dat_obj_write_u8(&dat, obj_3 + 2, 2));
        dat_assert(dat_obj_write_u8(&dat, obj_3 + 3, 3));
        dat_assert(dat_obj_set_ref(&dat, obj_3 + 4, obj_4));

        dat_assert(dat_obj_write_u32(&dat, obj_4, 4));

        uint8_t *buf = malloc(dat_file_export_max_size(&dat));
        uint32_t dat_size;
        dat_assert(dat_file_export(&dat, buf, &dat_size));

        FILE *f = fopen("test.dat", "wb+");
        fwrite(buf, dat_size, 1, f);
        fclose(f);
        
        free(buf);
        dat_assert(dat_file_destroy(&dat));
    } else if (strcmp(argv[1], "test") == 0) {
        uint8_t *buf = malloc(64*1024*1024);

        FILE *f = fopen("test.dat", "rb");
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        fread(buf, (size_t)size, 1, f);

        DatFile dat;
        dat_assert(dat_file_import(buf, (uint32_t)size, &dat));

        assert(strcmp(dat.symbols + dat.root_info[0].symbol_offset, "root_1") == 0);
        assert(strcmp(dat.symbols + dat.root_info[1].symbol_offset, "root_2") == 0);

        DatRef obj_1 = dat.root_info[0].data_offset;
        DatRef obj_2 = dat.root_info[1].data_offset;
        DatRef obj_3 = read_u32(&dat, obj_2 + 0);
        DatRef obj_4 = read_u32(&dat, obj_1 + 4);

        assert(read_u32(&dat, obj_1 + 0) == 0);
        assert(read_u32(&dat, obj_2 + 4) == 10000);
        assert(read_u16(&dat, obj_3 + 0) == 10);
        assert(read_u8(&dat, obj_3 + 2) == 20);
        assert(read_u8(&dat, obj_3 + 3) == 30);
        assert(read_u32(&dat, obj_3 + 4) == obj_4);
        assert(read_u32(&dat, obj_4 + 0) == 40);

        free(buf);
        dat_assert(dat_file_destroy(&dat));
    } else {
        fprintf(stderr, "invalid subcommand\n");
        return 1;
    }

    return 0;
}
