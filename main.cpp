#include "mbed.h"
#include "stdio.h"
#include "string.h"
#include "hex_file.h"

extern uint8_t const hex_file[];

typedef enum hex_parse_status_t hex_parse_status_t;
enum hex_parse_status_t {
    HEX_PARSE_OK = 0,
    HEX_PARSE_EOF,
    HEX_PARSE_UNALIGNED,
    HEX_PARSE_LINE_OVERRUN,
    HEX_PARSE_CKSUM_FAIL
};

// logic - Every buf 512 bytes
//  - Build and return structure
//  - partial structure needs to be persistent (2 of struct)
//  - line size doesnt matter
//  - always write decoded data to RAM

typedef enum hex_record_t hex_record_t;
enum hex_record_t {
    DATA_RECORD = 0,
    EOF_RECORD = 1,
    EXT_SEG_ADDR_RECORD = 2,
    START_SEG_ADDR_RECORD = 3,
    EXT_LINEAR_ADDR_RECORD = 4,
    START_LINEAR_ADDR_RECORD = 5
};
    

typedef union hex_line_t hex_line_t;
union __attribute__((packed)) hex_line_t {
    uint8_t buf[0x25];
    struct __attribute__((packed)) {
        uint8_t  byte_count;
        uint16_t address;
        uint8_t  record_type;
        uint8_t  data[0x20];
        uint8_t  checksum;
    };
};

/** Swap 16bit value - let compiler figure out the best way
 *  @param val a variable of size uint16_t to be swapped
 *  @return the swapped value
 */
static uint16_t swap16(uint16_t a)
{
    return ((a & 0x00ff) << 8) | ((a & 0xff00) >> 8);
}

/** Converts a character representation of a hex to real value.
 *   @param c is the hex value in char format
 *   @return the value of the hex
 */
static uint8_t ctoh(char c)
{
    return (c & 0x10) ? /*0-9*/ c & 0xf : /*A-F, a-f*/ (c & 0xf) + 9;
}

/** Calculate checksum on a hex record
 *   @param data is the line of hex record
 *   @param size is the length of the data array
 *   @return 1 if the data provided is a valid hex record otherwise 0
 */
static uint8_t validate_checksum(hex_line_t *record)
{
    uint8_t i = 0, result = 0;
    uint8_t test1, test2;
    for ( ; i < (record->byte_count+4); i++) {
        result += record->buf[i];
    }
    test1 = (~result)+1;
    test2 = record->buf[record->byte_count+4];
    return (test1 == test2);
    // record length unknown. checksum will always be at location byte_count + 4
    //return (record->buf[record->byte_count+4] == (uint8_t)(~result)+1);
}

void reset_hex_parser(void)
{

}

// still need to test need to complete a few states (using codepad.org)
hex_parse_status_t parse_hex_blob(uint8_t *hex_buf, uint32_t hex_buf_size, uint32_t *hex_amt_parsed, uint8_t *bin_buf, uint32_t bin_buf_size, uint32_t *bin_buf_address, uint32_t *bin_buf_num_bytes)
{
    static hex_line_t line = {0}, shadow_line = {0};
    static uint8_t low_nibble = 0, idx = 0, record_processed = 0;
    static uint32_t last_known_address = 0;
    static uint8_t load_unaligned_record = 0;
    uint8_t *end = hex_buf + hex_buf_size;
    // reset the amount of data that is being return'd
    *bin_buf_num_bytes = 0;

    // we had an exit state where the address was unaligned to the previous record and data count.
    //  Need to pop the last record into the buffer before decoding anthing else since it was 
    //  already decoded.
    if (load_unaligned_record) {
        // need some help...
        load_unaligned_record = 0;
        // move from line buffer back to input buffer
        memcpy((uint8_t *)bin_buf, (uint8_t *)shadow_line.data, shadow_line.byte_count);
        bin_buf += shadow_line.byte_count;
        bin_buf_num_bytes += shadow_line.byte_count;
        // this stores the last known start address of decoded data
        last_known_address = ((last_known_address & 0xffff0000) | shadow_line.address) + shadow_line.byte_count;
    }
    
    while (hex_buf != end) {
        switch ((uint8_t)(*hex_buf)) {
            // junk we dont care about could also just run the validate_checksum on &line
            case '\r':
            case '\n':
                // we've hit the end of an ascii line
                if (validate_checksum(&line) && !record_processed) {
                    record_processed = 1;
                    // address byteswap...
                    line.address = swap16(line.address);
                    switch (line.record_type) {
                        case DATA_RECORD:
                            // verify this is a continous block of memory or need to exit and dump
                            if (((last_known_address & 0xffff0000) | line.address) > (last_known_address + shadow_line.byte_count)) {
                                // keeping a record of the last hex record
                                memcpy(shadow_line.buf, line.buf, sizeof(hex_line_t));
                                *bin_buf_address = last_known_address - (uint32_t)(*bin_buf_num_bytes);
                                *hex_amt_parsed = (uint32_t)(end - hex_buf);
                                load_unaligned_record = 1;
                                return HEX_PARSE_UNALIGNED;
                            }
                        
                            // keeping a record of the last hex record
                            memcpy(shadow_line.buf, line.buf, sizeof(hex_line_t));
                            // move from line buffer back to input buffer
                            memcpy(bin_buf, line.data, line.byte_count);
                            bin_buf += line.byte_count;
                            *bin_buf_num_bytes = (uint32_t)(*bin_buf_num_bytes) + line.byte_count;
                            // this stores the last known start address of decoded data
                            last_known_address = ((last_known_address & 0xffff0000) | line.address) + line.byte_count;
                            break;
                        
                        case EOF_RECORD:
                            // fill in all FF here and force a return (or break from this logic)
                            memset(bin_buf, 0xff, (bin_buf_size - (uint32_t)(*bin_buf_num_bytes)));
                            // figure the start address before returning    
                            //*bin_buf_address = last_known_address - (uint32_t)(*bin_buf_num_bytes);
                            //*bin_buf_num_bytes = bin_buf_size;
                            return HEX_PARSE_EOF;
                        
                        case EXT_LINEAR_ADDR_RECORD:
                            // update the address msb's
                            last_known_address = (last_known_address & 0x0000ffff) | (line.data[0] << 24) | (line.data[1] << 16);
                            break;
                        
                        default:
                            break;
                    }
                } else {
                    return HEX_PARSE_CKSUM_FAIL;
                }
                break;
        
            // found start of a new record. reset state variables
            case ':':
                memset(line.buf, 0, sizeof(hex_line_t));
                low_nibble = 0;
                idx = 0;
                record_processed = 0;
                break;
            
            // decoding lines
            default:
                if (low_nibble) {
                    line.buf[idx] |= ctoh(*hex_buf) & 0xf;
                    idx++;
                }
                else {
                    if (idx < sizeof(hex_line_t)) {
                        line.buf[idx] = ctoh(*hex_buf) << 4;
                    }
                }
                low_nibble = !low_nibble;
                break;
        }
        hex_buf++;
    }
    
    memset(bin_buf, 0xff, (bin_buf_size - (uint32_t)(*bin_buf_num_bytes)));
    // figure the start address for the buffer before returning
    *bin_buf_address = last_known_address - (uint32_t)(*bin_buf_num_bytes);
    return HEX_PARSE_OK;
}

uint8_t *hex_loc = (uint8_t *)hex_file;
uint8_t bin_out_buf[256] = {0};

RawSerial pc(USBTX, USBRX);
    
int main()
{
    uint32_t address = 0, buf_written = 512, hex_block_size = 512, hex_written = 0;
    bin_out_buf[254] = 0xDE;
    bin_out_buf[255] = 0xAD;
    //printf("Size of hex file %d\n", sizeof(hex_file));
    //printf("Size of bin_buf %d\n", sizeof(bin_out_buf));
    while(1) {
        hex_parse_status_t status;
        do {
            status = parse_hex_blob(hex_loc, hex_block_size, &hex_written, bin_out_buf, sizeof(bin_out_buf), &address, &buf_written);
            if ((HEX_PARSE_EOF == status) || (HEX_PARSE_OK == status)) {
                if (hex_block_size != hex_written) {
                    // error state in parsing or record type
                    hex_written = hex_written;
                }
                //print the decoded file contents here
                for(int i = 0; i < buf_written; i++) {
                    pc.putc(bin_out_buf[i]);
                }
                hex_block_size = 512;
                hex_loc += 512;
            }
            if (HEX_PARSE_UNALIGNED == status) {
                //try to program the data here
                for(int i = 0; i < buf_written; i++) {
                    pc.putc(bin_out_buf[i]);
                }
                // pad the rest of the flash buffer with 0xff
                for(int i = buf_written; i < 512; i++) {
                    pc.putc(0xff);
                }
                hex_block_size = (512 - hex_written);
                hex_loc += hex_written;
            }
            if (HEX_PARSE_CKSUM_FAIL == status) {
                // programming failure recorded to usere here
                address = address;
                buf_written = buf_written;
            }
            
        } while(HEX_PARSE_EOF != status);
        // write the last bit of contents here
        for(int i = 0; i < buf_written; i++) {
            pc.putc(bin_out_buf[i]);
        }
        // pad the rest of the flash buffer with 0xff
        for(int i = buf_written; i < 512; i++) {
            pc.putc(0xff);
        }
        error("");
    }
}
