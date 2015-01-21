#include "mbed.h"
#include "stdio.h"
#include "string.h"

typedef enum hex_parse_status_t hex_parse_status_t;
enum hex_parse_status_t {
    HEX_PARSE_OK = 0,
    HEX_PARSE_EOF,
    HEX_PARSE_UNALIGNED,
    HEX_PARSE_LINE_OVERRUN
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
    for ( ; i < (record->byte_count+4); i++) {
        result += record->buf[i];
    }
    // record length unknown. checksum will always be at location byte_count + 4
    return (record->buf[record->byte_count+4] == (uint8_t)(~result)+1);
}

void reset_hex_parser(void)
{

}
// still need to test need to complete a few states (using codepad.org)
hex_parse_status_t parse_hex_blob(uint8_t *buf, uint32_t *address, uint32_t *size)
{
    static hex_line_t line, shadow_line;
    static uint8_t low_nibble = 0, idx = 0, record_processed = 0;
    static uint32_t base_address = 0;
    static uint8_t unload_unaligned_record = 0;
    // were gonna store decoded data in ourself... scary
    uint8_t *input_buf = buf;
    uint8_t *end = buf + (uint32_t)(*size);
    uint32_t input_buf_size = (uint32_t)(*size);
    // reset the amount of data that is being return'd
    *size = 0;
    
    // we had an exit state when the data was unaligned. Need to pop in the buffer
    //  before decoding anthing else since it was already decoded
    if (unload_unaligned_record) {
        unload_unaligned_record = 0;
        // move from line buffer back to input buffer
        memcpy((uint8_t *)input_buf, (uint8_t *)shadow_line.data, shadow_line.byte_count);
        input_buf += shadow_line.byte_count;
        size += shadow_line.byte_count;
        // this stores the last known start address of decoded data
        *address = base_address + shadow_line.address + shadow_line.byte_count;
    }
    
    while (buf != end) {
        switch ((uint8_t)(*buf)) {
            // junk we dont care about
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
                            if ((base_address + line.address) > ((uint32_t)(*address) + line.byte_count)) {
                                // figure the start address before returning
                                *address = (uint32_t)(*address) - (uint32_t)(*size);
                                // need to unload this decoded data somewhere til next call
                                memcpy(line.buf, shadow_line.buf, sizeof(hex_line_t));
                                unload_unaligned_record = 1;
                                return HEX_PARSE_UNALIGNED;
                            }
                        
                            // move from line buffer back to input buffer
                            memcpy((uint8_t *)input_buf, (uint8_t *)line.data, line.byte_count);
                            input_buf += line.byte_count;
                            *size = (uint32_t)(*size) + line.byte_count;
                            // this stores the last known start address of decoded data
                            *address = base_address + line.address + line.byte_count;
                            break;
                        
                        case EOF_RECORD:
                            // fill in all FF here and force a return (or break from this logic)
                            memset(input_buf, 0xff, (input_buf_size - (uint32_t)(*size)));
                         // figure the start address before returning    
                            *address = (uint32_t)(*address) - (uint32_t)(*size);
                            *size = input_buf_size;
                            return HEX_PARSE_EOF;
                        
                        case EXT_LINEAR_ADDR_RECORD:
                            // update the address msb's
                            base_address = (line.data[0] << 24) | (line.data[1] << 16);
                            break;
                        
                        default:
                            break;
                    }
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
                    line.buf[idx] |= ctoh(*buf) & 0xf;
                    idx++;
                }
                else {
                    if (idx < sizeof(hex_line_t)) {
                        line.buf[idx] = ctoh(*buf) << 4;
                    }
                }
                low_nibble = !low_nibble;
                break;
        }
        buf++;
    }
    
    memset(input_buf, 0xff, (input_buf_size - (uint32_t)(*size)));
    // figure the start address for the buffer before returning - this is calculated wrongly..
    *address = (uint32_t)(*address) - (uint32_t)(*size);
    return HEX_PARSE_OK;
}

uint8_t hex_file[] = ":020000040000FA\n"
":10000000C0070000D1060000D1000000B1060000CA\n"
":1000100000000000000000000000000000000000E0\n"
":100020000000000000000000000000005107000078\n"
":100030000000000000000000DB000000E500000000\n"
":10004000EF000000F9000000030100000D010000B6\n"
":1000500017010000210100002B0100003501000004\n"
":100060003F01000049010000530100005D01000054\n"
":1000700067010000710100007B01000085010000A4\n"
":100080008F01000099010000A3010000AD010000F4\n"
":10009000B7010000C1010000CB010000D501000044\n"
":1000A000DF010000E9010000F3010000FD01000094\n"
":1000B00007020000110200001B02000025020000E0\n"
":1000C0001FB5C046C04600F0EFFA04B00FB41FBD24\n"
":1000D00008205A49096809580847382057490968CB\n"
":1000E000095808473C2055490968095808474020E5\n"
":1000F0005249096809580847442050490968095875\n"
":10010000084748204D490968095808474C204B4981\n"
":10011000096809580847502048490968095808479C\n"
":100120005420464909680958084758204349096836\n"
":10013000095808475C204149096809580847602068\n"
":100140003E4909680958084764203C49096809582C\n"
":100150000847682039490968095808476C20374919\n"
":100160000968095808477020344909680958084740\n"
":100170007420324909680958084778202F490968CE\n"
":10018000095808477C202D490968095808478020EC\n"
":100190002A490968095808478420284909680958E4\n"
":1001A0000847882025490968095808478C202349B1\n"
":1001B00009680958084790202049096809580847E4\n"
":1001C00094201E4909680958084798201B49096866\n"
":1001D000095808479C201949096809580847A02070\n"
":1001E0001649096809580847A4201449096809589C\n"
":1001F0000847A8201149096809580847AC200F4949\n"
":10020000096809580847B0200C4909680958084787\n"
":10021000B4200A49096809580847B82007490968FD\n"
":1002200009580847BC2005490968095808470000D3\n"
":00000001FF";

int main()
{
    uint32_t address = 0, buf_size = 512;
    printf("Size of hex file %d\n", sizeof(hex_file));
    while(1) {
        hex_parse_status_t status;
        do {
            status = parse_hex_blob(hex_file, &address, &buf_size);
            if (status == HEX_PARSE_OK) {
                //try to program the data here
                address = address;
                buf_size = buf_size;
            }
            if (status == HEX_PARSE_UNALIGNED) {
                //try to program the data here
                address = address;
                buf_size = buf_size;
            }
            
        } while(status != HEX_PARSE_EOF);
    }
}
