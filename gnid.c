#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include<sys/types.h> //! Types Aliass
#include<net/ethernet.h>
#include<unistd.h>
#include<net/if.h>
#include<net/if_media.h>
#include<string.h>
#include<errno.h>
#include<stdbool.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <assert.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <json-c/json_object_iterator.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/reboot.h>
#include <strings.h>
#include <yaml.h>
#include <time.h>
#include <libusb.h>
#include <ctype.h>
#include <openssl/sha.h>
//! sysctl
#include <sys/types.h>
#include <sys/sysctl.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <string.h>
#include <errno.h>


#define CRC64_POLY 0x42F0E1EBA9EA3693ULL
#define CRC64_INIT 0xFFFFFFFFFFFFFFFFULL
#define HTTP_MAX_RESPONSE_SIZE 1024
#define MAX_INTERFACES 20
#define MAX_KEY_SIZE 16
#define MAX_VALUE_SIZE 64
#define SUCCESS_COUNT 2
#define GNID_ACCESS_TOKEN_FILEPATH "/var/db/tid.db"
#define GNID_REGISTER_ID_FILEPATH "/var/db/id.db"
#define GNID_REGISTER_EXPIRE_FILEPATH "/var/db/eid.db"
#define GNID_VERIFICATION_FILEPATH "/var/db/fw.json"
#define GNID_DIGEST_SIZE     32U
#define GNID_TRUNCATE_TOKEN_SIZE 16U
//#define DEBUG_GENID
//! cc gnid.c -o gnid -lcrypto -ljson-c -lcurl -lusb -L/usr/local/lib -I/usr/local/include


typedef struct{
	char* key;
	char* value;
}KeyValue_t;
typedef struct {
    uint32_t size;
	KeyValue_t data[MAX_INTERFACES];
}Layer2Vector_t;
int Layer2Vector_Init(Layer2Vector_t* _vector){
    if(_vector == NULL) return 0;
	_vector->size = 0;
    return 0;
}
int Layer2Vector_insert(Layer2Vector_t* _vector,const char* _key, const char* _value){
    if(_vector == NULL || _vector->size == MAX_INTERFACES || _key == NULL || _value == NULL) return 0;
	size_t _keylen = strlen(_key) + 1;
	size_t _valuelen = strlen(_value) + 1;
	_keylen = _keylen > MAX_KEY_SIZE + 1 ? MAX_KEY_SIZE + 1 : _keylen;
	_valuelen = _valuelen > MAX_VALUE_SIZE + 1 ? MAX_VALUE_SIZE + 1 : _valuelen;
	_vector->data[_vector->size].key = (char*)malloc(_keylen);
	_vector->data[_vector->size].value = (char*)malloc(_valuelen);
	if(_vector->data[_vector->size].key && _vector->data[_vector->size].value){
		snprintf(_vector->data[_vector->size].key,_keylen,"%s",_key);
		snprintf(_vector->data[_vector->size].value,_valuelen,"%s",_value);
		_vector->size++;
		return 1;
	}
    return 0;
}
KeyValue_t Layer2Vector_remove(Layer2Vector_t* _vector){
	KeyValue_t _item = {NULL, NULL};
    if(_vector == NULL || _vector->size == 0) return _item;
	//! Free Key
	if(_vector->data[_vector->size-1].key){
		_item.key = strdup(_vector->data[_vector->size-1].key);
		free(_vector->data[_vector->size-1].key);
	}
	//! Free Value
	if(_vector->data[_vector->size-1].value){
		_item.value = strdup(_vector->data[_vector->size-1].value);
		free(_vector->data[_vector->size-1].value);
	}
	//! Increase Size
    _vector->size--;
	
    return _item;
}
void Layer2Vector_PrintAll(Layer2Vector_t* _vector){
    if(_vector){
        for(int i = 0; i < _vector->size; i++){
			if(_vector->data[i].key && _vector->data[i].value)
            	fprintf(stdout,"[%s]=>[%s]\n",_vector->data[i].key, _vector->data[i].value);
        }   
    }
}
int Layer2Vector_DeInit(Layer2Vector_t* _vector){
    if(_vector == NULL) return 0;
    //! Free Size
    for(int i = 0; i < _vector->size; ++i){
        if(_vector->data[i].key) free(_vector->data[i].key);
		if(_vector->data[i].value) free(_vector->data[i].value);
    }
	_vector->size = 0;
    return 0;
}
size_t GenID_WriteCallback(void *contents, size_t size, size_t nmemb, void *odata){
	size_t total_size = size * nmemb;
	char* ptrodata = (char*)odata;
	if(total_size < HTTP_MAX_RESPONSE_SIZE-1){
	    strncpy(odata,contents,total_size);
		ptrodata[total_size] = '\0';
	}else{
		ptrodata[total_size] = '\0';
	}
	return total_size;
}

typedef struct{
	struct libusb_device* _device;
	struct libusb_device_handle* _device_handle;
	struct libusb_endpoint_descriptor* _ep_desc;
	int _interface_no;
	int _alt_interface;
}SecurityKey_t;
#define FOS_PROTO_VENDOR_ID 0x0483
#define FOS_PROTO_VENDOR_STRING "ThingzEye"
#define FOS_PROTO_PRODUCT_ID 0x5740
#define FOS_PROTO_PRODUCT_STRING "SecurityKey"
//! Frame Properties
#define FOS_PROTO_SECURITY_KEY_MAGIC_H 0xCC
#define FOS_PROTO_SECURITY_KEY_MAGIC_L 0xDD
#define FOS_PROTO_QUERY_KEY_REQ_TYPE  0x6B
#define FOS_PROTO_QUERY_KEY_RESP_TYPE 0x73
//! USB Endpoints
#define BULK_EP_OUT     0x81
#define BULK_EP_IN      0x01

int GenID_ReadUUID(char*);
int GenID_ReadUUID_Ex(char*);
int GenID_CalcCRC64(const uint8_t*, const size_t, uint64_t*);
int GenID_CalcKey(const uint8_t*, const size_t,char**);
int GenID_CalcDigest(uint8_t*,size_t,uint8_t*,size_t, char**);
int GenID_GetAllEthernetAddresses(Layer2Vector_t*);
int GenID_GetJsonOf(const Layer2Vector_t*, char*, const size_t);
int GenID_GetScrambledEggs(int*, const size_t);
int GenID_Dump(const char*, const char*);
int GenID_Load(const char*, char*, size_t);
int GenID_DoRegister(const char*, const char*);
int GenID_DoCheckRegister(const char*, const char*);
//! New Things
int GenID_GetAllEthernetAddressesFromFile(Layer2Vector_t*);
int GenID_VerifyOffline(const Layer2Vector_t*);
int GenID_SecurityKey_WriteFrame(SecurityKey_t*,uint8_t*, uint8_t);
int GenID_SecurityKey_ReadFrame(SecurityKey_t* ,uint8_t* , uint8_t,int*);
uint16_t GenID_SecurityKey_CRC16(uint8_t*, uint8_t);
int GNID_SecurityKey_CheckResp(SecurityKey_t*,uint8_t*, char*);
int GenID_SecurityKey_QueryKey(SecurityKey_t*,uint8_t*);
int GenID_SecurityKey_CheckResp(SecurityKey_t*,uint8_t*, char*);
int GenID_SecurityKey_isConnected_ex(libusb_context*,SecurityKey_t*);
int GenID_PHP_RunScript(const char*);
void GenID_DisplayLANConfigurationMenu(void);
int GenID_IsSecurityConnected(libusb_context*);
int GenID_VerifyUsingSecurityKey(void);
int GenID_GenerateToken(void);


int main(int argc, char* argv[]){
    if(argc == 1){
		char regid[100] = {0};
		if(GenID_Load(GNID_REGISTER_ID_FILEPATH,regid,sizeof(regid)) != -1 && strlen(regid) >= 32){
			fprintf(stdout,"%s",regid);
		}
    }else if(argc == 2){
		char flag[16] = {0};
        if(strlen(argv[1]) == 13 && strcmp(argv[1],"thingzeye-reg") == 0 || strcmp(argv[1],"thingzeye-ver") == 0){
            snprintf(flag,sizeof(flag), "%s",argv[1]);
			char access_token[100];
			if(GenID_Load(GNID_ACCESS_TOKEN_FILEPATH,access_token,sizeof(access_token))){
				#ifdef DEBUG_GENID
					fprintf(stdout,"Token: %s\n",access_token);
				#endif
				Layer2Vector_t orignal_addrs;
				Layer2Vector_Init(&orignal_addrs);
				if(GenID_GetAllEthernetAddresses(&orignal_addrs)){
					#ifdef DEBUG_GENID
					   Layer2Vector_PrintAll(&orignal_addrs);
					#endif
					char layers2json_str[1024];
					char registration_id[100];
					
					if(GenID_GetJsonOf(&orignal_addrs,layers2json_str,sizeof(layers2json_str))){
						#ifdef DEBUG_GENID
						fprintf(stdout,"%s\n",layers2json_str);
						#endif
						if(strcmp(flag,"thingzeye-reg") == 0 && GenID_DoRegister(layers2json_str,access_token)){
							fprintf(stdout,"Registration Success...\n");
						}else if(strcmp(flag,"thingzeye-ver") == 0){
							if(GenID_VerifyOffline(&orignal_addrs)){
								fprintf(stdout,"[offline] Authentication Successful\n");
							}else if(GenID_Load(GNID_REGISTER_ID_FILEPATH,registration_id,sizeof(registration_id)) && GenID_DoCheckRegister(layers2json_str,registration_id)){
								fprintf(stdout,"[Online] Authentication Successful\n");
							}else if(GenID_VerifyUsingSecurityKey()){
								fprintf(stdout,"[SecKey] Authentication Successful\n");
							}else{
								//! Clear
								Layer2Vector_DeInit(&orignal_addrs);
								fprintf(stderr,"Rebooting...\n");
								reboot(RB_AUTOBOOT);
							}
						}
					}
				}
				Layer2Vector_DeInit(&orignal_addrs);
			}
		}else if(strlen(argv[1]) == 13 && strcmp(argv[1],"thingzeye-gen") == 0){
			fprintf(stdout,"Token Generation[%s]\n",GenID_GenerateToken()? "Success":"Failure");
		}
    }
    return 0;
}
int GenID_GenerateToken(void){
	uint8_t _tmp_itoken[GNID_DIGEST_SIZE];
	uint8_t _tmp_digest[GNID_DIGEST_SIZE];
	uint8_t _tmp_otoken[GNID_TRUNCATE_TOKEN_SIZE];
	time_t _ctime = time(NULL);
	srand(_ctime);
	for(int i = 0; i < sizeof(_tmp_itoken); i++){
		_tmp_itoken[i] = rand();
	}
	if(SHA256(_tmp_itoken,GNID_DIGEST_SIZE,_tmp_digest) != NULL){
		_tmp_otoken[0] = _tmp_digest[0] ^ _tmp_digest[2];
		_tmp_otoken[1] = _tmp_digest[4] ^ _tmp_digest[6];
		_tmp_otoken[2] = _tmp_digest[8] ^ _tmp_digest[10];
		_tmp_otoken[3] = _tmp_digest[12] ^ _tmp_digest[14];
		_tmp_otoken[4] = _tmp_digest[16] ^ _tmp_digest[18];
		_tmp_otoken[5] = _tmp_digest[20] ^ _tmp_digest[22];
		_tmp_otoken[6] = _tmp_digest[24] ^ _tmp_digest[26];
		_tmp_otoken[7] = _tmp_digest[28] ^ _tmp_digest[30];
		_tmp_otoken[8] = _tmp_digest[31] ^ _tmp_digest[29];
		_tmp_otoken[9] = _tmp_digest[27] ^ _tmp_digest[25];
		_tmp_otoken[10] = _tmp_digest[23] ^ _tmp_digest[21];
		_tmp_otoken[11] = _tmp_digest[19] ^ _tmp_digest[17];
		_tmp_otoken[12] = _tmp_digest[15] ^ _tmp_digest[13];
		_tmp_otoken[13] = _tmp_digest[11] ^ _tmp_digest[9];
		_tmp_otoken[14] = _tmp_digest[7] ^ _tmp_digest[5];
		_tmp_otoken[15] = _tmp_digest[3] ^ _tmp_digest[1];
		char* data = (char*)malloc(GNID_TRUNCATE_TOKEN_SIZE*2+1);
		if(data){
			int i = 0;
			char* ptr = data;
			while(i < GNID_TRUNCATE_TOKEN_SIZE){
				sprintf(ptr,"%02x",_tmp_otoken[i]);
				ptr += 2;
				i++;
			}
			ptr = NULL;
			if(GenID_Dump(GNID_ACCESS_TOKEN_FILEPATH,data)){
				free(data);
				return 1;
			}else{
				free(data);
				return 0;
			}
		}
	}
    return 0;
}
int GenID_SecurityKey_WriteFrame(SecurityKey_t* _device_key,uint8_t* _frame, uint8_t _framelen){
	if(_device_key != NULL && _device_key->_device_handle != NULL && _frame != NULL && _framelen > 0){
		int bytes_sent = 0;
		int errcode = libusb_bulk_transfer(_device_key->_device_handle,BULK_EP_IN,_frame,_framelen,&bytes_sent,5000); //! Timeout 5s
		#ifdef APP_DEBUG
		fprintf(stdout,"GenID_SecurityKey_WriteFrame: %s %d\n",libusb_strerror(errcode),bytes_sent);
		#endif
		if(errcode != 0){
				libusb_release_interface(_device_key->_device_handle,0);
				libusb_close(_device_key->_device_handle);
				return 0;
		}
		return 1;
	}
    return 0;
}
int GenID_SecurityKey_ReadFrame(SecurityKey_t* _device_key,uint8_t* _frame, uint8_t _framelen,int* bytes_received){
	if(_device_key != NULL && _device_key->_device_handle != NULL && _frame != NULL && _framelen > 0 && bytes_received != NULL){
		*bytes_received = 0;
		int errcode = libusb_bulk_transfer(_device_key->_device_handle,BULK_EP_OUT,_frame,_framelen,bytes_received,5000); //! Timeout 5s
		#ifdef APP_DEBUG
		fprintf(stdout,"GenID_SecurityKey_ReadFrame: %s %d\n",libusb_strerror(errcode),*bytes_received);
		for(int i = 0; i < *bytes_received; i++){
			fprintf(stdout,"%x ",_frame[i]);
		}
		fprintf(stdout,"\n");
		#endif
		libusb_release_interface(_device_key->_device_handle,0);
		libusb_close(_device_key->_device_handle);
		return errcode != 0? 0 : 1;
	}
    return 0;
}
uint16_t GenID_SecurityKey_CRC16(uint8_t* buffer, uint8_t buffersize){
    uint16_t crc = 0xFFFF;
    for(int i = 0; i < buffersize; i++){
                crc ^= buffer[i];
                for(int j = 1; j <= 8; j++){
                        if((crc & 0x0001) != 0){
                            crc >>= 1;
                                crc ^= 0xA001;
                        }else
                                crc >>= 1;
                }
        }
    uint16_t temp = crc >> 8;
        crc = (crc << 8) | temp;
        crc &= 0xFFFF;
        return crc;
}
int GNID_SecurityKey_CheckResp(SecurityKey_t* _security_key,uint8_t* _buffer, char* _osecret){
        if(_buffer == NULL || _security_key == NULL || _osecret == NULL) return 0;
        //! Read Unimplemented yet
        int read_size = 0;
        uint8_t read_buffer[50] = {0};
        if(GenID_SecurityKey_ReadFrame(_security_key,read_buffer,sizeof(read_buffer),&read_size) != -1){
                
                uint16_t crc = GenID_SecurityKey_CRC16(read_buffer,read_size-2);
            //! CRC
                if(read_buffer[read_size-1] == (crc & 0xFF) && read_buffer[read_size-2] == ((crc >> 8) & 0xFF)){
                        
                        //! Magic
                        if(read_buffer[0] == FOS_PROTO_SECURITY_KEY_MAGIC_H && read_buffer[1] == FOS_PROTO_SECURITY_KEY_MAGIC_L){
                                
                                //! QueryResponse
                                if(read_buffer[2] == FOS_PROTO_QUERY_KEY_RESP_TYPE){
                                        
                                        //! Validate Payload Size
                                        int payloadsize = read_size - 2 - 2 - 1 - 1;
                                        if(read_buffer[3] == payloadsize && payloadsize >= 4 + 4 + 4){
                                                
                                                //! Handle Replay Attack
                                                if(read_buffer[4] == _buffer[0] && read_buffer[5] == _buffer[1] && read_buffer[6] == _buffer[2] && read_buffer[7] == _buffer[3]){
                                                         
                                                        //! Length Extension and Injection Attack
                                                        uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
                                                        SHA256(&read_buffer[2],read_size-2-2-4,hash);
                                                        if(hash[read_buffer[8]] == read_buffer[read_size-6] && hash[read_buffer[9]] == read_buffer[read_size-5] && hash[read_buffer[10]] == read_buffer[read_size-4] && hash[read_buffer[11]] == read_buffer[read_size-3]){
                                                                
                                                                int user_secret_size = payloadsize - 4 - 4- 4;
                                                                char ptr[3];
                                                                int i = 12;
                                                                _osecret[0]='\0';
                                                                for(;i < 12 + user_secret_size; i++){
                                                                        snprintf(ptr,3,"%02x",read_buffer[i]);
                                                                        strncat(_osecret,ptr,3);
                                                                }
                                                                return 1;
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }
        return 0;
}
int GenID_SecurityKey_QueryKey(SecurityKey_t* _security_key,uint8_t* _buffer){
        if(_buffer == NULL || _security_key == NULL) return 0;
        time_t random_bytes = time(NULL);
        uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
        srand((unsigned) time(NULL));
        uint8_t frame[18];
    frame[0] = FOS_PROTO_SECURITY_KEY_MAGIC_H;
    frame[1] = FOS_PROTO_SECURITY_KEY_MAGIC_L;
    frame[2] = FOS_PROTO_QUERY_KEY_REQ_TYPE ;
    frame[3] = 4U + 4U + 4U;
//! Payload
    //! Replay Handle
        _buffer[0] = frame[4] = ((random_bytes >> 24U) & 0xFF) | 0x04;
        _buffer[1] = frame[5] = ((random_bytes >> 16U) & 0xFF) | 0x05;
        _buffer[2] = frame[6] = ((random_bytes >>  8U) & 0xFF) | 0x06;
        _buffer[3] = frame[7] = ((random_bytes >>  0U) & 0xFF) | 0x07;
        //! Injection Handle
        frame[8]  = (rand() % SHA256_DIGEST_LENGTH);
        frame[9]  = (rand() % SHA256_DIGEST_LENGTH);
        frame[10] = (rand() % SHA256_DIGEST_LENGTH);
        frame[11] = (rand() % SHA256_DIGEST_LENGTH);
        //! Digest
        SHA256(&frame[2],10,hash);
        frame[12] = hash[frame[8]];
        frame[13] = hash[frame[9]];
        frame[14] = hash[frame[10]];
        frame[15] = hash[frame[11]];
        //! CRC
        uint16_t crc = GenID_SecurityKey_CRC16(frame,sizeof(frame)-2);
        frame[16] = crc & 0xFF;
        frame[17] = (crc >> 8) & 0xFF;
        //! Write
        return GenID_SecurityKey_WriteFrame(_security_key,frame,sizeof(frame));
}
int GenID_SecurityKey_CheckResp(SecurityKey_t* _security_key,uint8_t* _buffer, char* _osecret){
        if(_buffer == NULL || _security_key == NULL || _osecret == NULL) return -1;
        //! Read Unimplemented yet
        int read_size = 0;
        uint8_t read_buffer[50] = {0};
        if(GenID_SecurityKey_ReadFrame(_security_key,read_buffer,sizeof(read_buffer),&read_size) != -1){
                
                uint16_t crc = GenID_SecurityKey_CRC16(read_buffer,read_size-2);
            //! CRC
                if(read_buffer[read_size-1] == (crc & 0xFF) && read_buffer[read_size-2] == ((crc >> 8) & 0xFF)){
                        
                        //! Magic
                        if(read_buffer[0] == FOS_PROTO_SECURITY_KEY_MAGIC_H && read_buffer[1] == FOS_PROTO_SECURITY_KEY_MAGIC_L){
                                
                                //! QueryResponse
                                if(read_buffer[2] == FOS_PROTO_QUERY_KEY_RESP_TYPE){
                                        
                                        //! Validate Payload Size
                                        int payloadsize = read_size - 2 - 2 - 1 - 1;
                                        if(read_buffer[3] == payloadsize && payloadsize >= 4 + 4 + 4){
                                                
                                                //! Handle Replay Attack
                                                if(read_buffer[4] == _buffer[0] && read_buffer[5] == _buffer[1] && read_buffer[6] == _buffer[2] && read_buffer[7] == _buffer[3]){
                                                         
                                                        //! Length Extension and Injection Attack
                                                        uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
                                                        SHA256(&read_buffer[2],read_size-2-2-4,hash);
                                                        if(hash[read_buffer[8]] == read_buffer[read_size-6] && hash[read_buffer[9]] == read_buffer[read_size-5] && hash[read_buffer[10]] == read_buffer[read_size-4] && hash[read_buffer[11]] == read_buffer[read_size-3]){
                                                                
                                                                int user_secret_size = payloadsize - 4 - 4- 4;
                                                                char ptr[3];
                                                                int i = 12;
                                                                _osecret[0]='\0';
                                                                for(;i < 12 + user_secret_size; i++){
                                                                        snprintf(ptr,3,"%02x",read_buffer[i]);
                                                                        strncat(_osecret,ptr,3);
                                                                }
                                                                return 1;
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }
        return -1;
}
int GenID_SecurityKey_isConnected_ex(libusb_context* app_contex,SecurityKey_t* _device_key){
        if(_device_key == NULL || app_contex == NULL) return -1;
        libusb_device** device_list;
        int is_device_found = 0;
    int errcode = -1;
        _device_key->_device = NULL;
        _device_key->_device_handle = NULL;
        _device_key->_ep_desc = NULL;
        _device_key->_interface_no = -1;
        _device_key->_alt_interface = -1;
        errcode = libusb_get_device_list(app_contex, &device_list);
    if(errcode < 0) {
        fprintf(stderr, "[E] [libusb_get_device_list] %s\n", libusb_error_name(errcode));
        return -1;
    }
        int device_list_size = errcode;
        for(ssize_t i = 0; i < device_list_size; i++){
                struct libusb_device_descriptor device_detail;
                uint8_t vendor_name[100];
                uint8_t product_name[100];
                errcode = libusb_get_device_descriptor(device_list[i],&device_detail);
                if (errcode < 0) {
                fprintf(stderr, "[E] [libusb_get_device_descriptor] %s\n", libusb_error_name(errcode));
                continue;
                }
                libusb_device_handle *device_handle = NULL;
        errcode = libusb_open(device_list[i], &device_handle);
        if (errcode < 0) {
            fprintf(stderr, "[E] [libusb_open] %s\n", libusb_error_name(errcode));
            continue;
        }
        int actual_size = libusb_get_string_descriptor_ascii(device_handle, device_detail.iManufacturer, vendor_name, sizeof(vendor_name));
        if(actual_size < 0){
                        libusb_close(device_handle);
            fprintf(stderr, "[E] [libusb_get_string_descriptor_ascii-iVendor] %s\n", libusb_error_name(actual_size));
            continue;
                }
                vendor_name[actual_size] = '\0';
                actual_size = libusb_get_string_descriptor_ascii(device_handle, device_detail.iProduct, product_name, sizeof(product_name));
        if(actual_size < 0){
                        libusb_close(device_handle);
            fprintf(stderr, "[E] [libusb_get_string_descriptor_ascii-iProduct] %s\n", libusb_error_name(actual_size));
            continue;
                }
                product_name[actual_size] = '\0';
                #ifdef APP_DEBUG
                fprintf(stdout,"%s\n",vendor_name);
                fprintf(stdout,"%s\n",product_name);
            fprintf(stdout,"%x\n",device_detail.idVendor);
                fprintf(stdout,"%x\n",device_detail.idProduct );
                fprintf(stdout,"--------------------------\n");
                #endif
                if(strncmp((const char*)vendor_name,FOS_PROTO_VENDOR_STRING,strlen(FOS_PROTO_VENDOR_STRING)) == 0 && strncmp((const char*)product_name,FOS_PROTO_PRODUCT_STRING,strlen(FOS_PROTO_PRODUCT_STRING)) == 0 && device_detail.idVendor == FOS_PROTO_VENDOR_ID && device_detail.idProduct == FOS_PROTO_PRODUCT_ID){
                _device_key->_device_handle = device_handle;
                        _device_key->_device = device_list[i];
            #ifdef APP_DEBUG
                        fprintf(stdout,"DeviceNo: %zd\n",i);
                        fprintf(stdout,"\tDeviceMajorMinor: [0x%04x:0x%04x] \n",device_detail.idVendor,device_detail.idProduct);
                        fprintf(stdout,"\tDeviceVendorName: %s\n",vendor_name);
                        fprintf(stdout,"\tDeviceProductName: %s\n",product_name);
                        #endif
                        struct libusb_config_descriptor *config;
                        errcode = libusb_get_active_config_descriptor(device_list[i], &config);
            if (errcode < 0) {
                fprintf(stderr, "[E] [libusb_get_active_config_descriptor] %s\n", libusb_error_name(errcode));
            }else{
                                //! Get Configuration
                                int device_config;
                                errcode = libusb_get_configuration(device_handle,&device_config);
                                if(errcode == 0){
                                        //! Set Configuration if not set
                                        if(device_config != 1){
                                            errcode = libusb_set_configuration(device_handle, 1);
                                                if(errcode != 0) break;
                                        }
                                        //! Claim Interface
                                        errcode = libusb_claim_interface(device_handle, 0);
                                        if(errcode == 0){
                                                //! Activate Configuration
                                                is_device_found = 1;
                                                for(uint8_t j = 0; j < config->bNumInterfaces; ++j) {
                                                        const struct libusb_interface *itf = &config->interface[j];
                                                        for(uint8_t k = 0; k < itf->num_altsetting; ++k) {
                                                                const struct libusb_interface_descriptor *itf_desc = &itf->altsetting[k];
                                                                for(int k = 0; k < itf_desc->bNumEndpoints; k++){
                                                                        const struct libusb_endpoint_descriptor *ep_desc = &itf_desc->endpoint[k];
                                                                        _device_key->_interface_no = itf_desc->bInterfaceNumber;
                                                                        _device_key->_alt_interface = itf_desc->bAlternateSetting;
                                                                        _device_key->_ep_desc = ep_desc;
                                                                        #ifdef APP_DEBUG
                                                                        fprintf(stdout,"\nEndPoint Descriptors: ");
                                                                        fprintf(stdout,"\n\tSize of EndPoint Descriptor: %d", ep_desc->bLength);
                                                                        fprintf(stdout,"\n\tType of Descriptor: %d", ep_desc->bDescriptorType);
                                                                        fprintf(stdout,"\n\tEndpoint Address: 0x0%x", ep_desc->bEndpointAddress);
                                                                        fprintf(stdout,"\n\tMaximum Packet Size: %x", ep_desc->wMaxPacketSize);
                                                                        fprintf(stdout,"\n\tAttributes applied to Endpoint: %d", ep_desc->bmAttributes);
                                                                        fprintf(stdout,"\n\tInterval for Polling for data Transfer: %d\n", ep_desc->bInterval);
                                                                        #endif
                                                                }
                                                        }
                                                }
                                        }

                                }
                                libusb_free_config_descriptor(config);
                        }
                        break;
        }
        libusb_close(device_handle);
        }
        libusb_free_device_list(device_list,1);
        return is_device_found;
}
int GenID_PHP_RunScript(const char* _script){
    pid_t pid;
    int status;
    pid = fork();
    if (pid == 0) {
        execlp("/usr/local/bin/php", "php", _script, NULL);
        perror("execlp");
        return 0;
    }else if(pid < 0) {
        perror("fork");
        return 0;
    }else{
        waitpid(pid, &status, 0);
    }
    return 1;
}
void GenID_DisplayLANConfigurationMenu(void){
	int option = -1;
	char script_filepath[100];
	char input_string[24];
	while(1){
		fprintf(stdout,"\n-: ThingzEye Firewall Menu :-\n");
		fprintf(stdout,"1) Assign Interfaces\n");
		fprintf(stdout,"2) Set interface(s) IP address\n");
		fprintf(stdout,"3) Reboot system\n");
		fprintf(stdout,"4) Cont.\n");
		fprintf(stdout,"Enter an option: ");
		fgets(input_string,24,stdin);
		input_string[strcspn(input_string, "\n")] = '\0';
		option = atoi(input_string);
		switch(option){
			case 1:
				snprintf(script_filepath,100,"%s","/etc/rc.initial.setports");
				GenID_PHP_RunScript(script_filepath);
			break;
			case 2:
				snprintf(script_filepath,100,"%s","/etc/rc.initial.setlanip");
				GenID_PHP_RunScript(script_filepath);
			break;
			case 3:
				snprintf(script_filepath,100,"%s","/etc/rc.initial.reboot");
				GenID_PHP_RunScript(script_filepath);
			break;
			case 4:
					return;
		}
	}
}
int GenID_IsSecurityConnected(libusb_context* app_contex){
    if(app_contex == NULL) return 0;
    libusb_device** device_list;
    int is_device_found = 0;
    int errcode = -1;
    errcode = libusb_get_device_list(app_contex, &device_list);
    if(errcode < 0) {
        fprintf(stderr, "[E] [libusb_get_device_list] %s\n", libusb_error_name(errcode));
        return -1;
    }
	int device_list_size = errcode;
	for(ssize_t i = 0; i < device_list_size; i++){
		struct libusb_device_descriptor device_detail;
		uint8_t vendor_name[100];
		uint8_t product_name[100];
		errcode = libusb_get_device_descriptor(device_list[i],&device_detail);
		if (errcode < 0) {
			fprintf(stderr, "[E] [libusb_get_device_descriptor] %s\n", libusb_error_name(errcode));
			continue;
		}
		libusb_device_handle *device_handle = NULL;
		errcode = libusb_open(device_list[i], &device_handle);
		if (errcode < 0) {
			fprintf(stderr, "[E] [libusb_open] %s\n", libusb_error_name(errcode));
			continue;
		}
		int actual_size = libusb_get_string_descriptor_ascii(device_handle, device_detail.iManufacturer, vendor_name, sizeof(vendor_name));
		if(actual_size < 0){
			libusb_close(device_handle);
			fprintf(stderr, "[E] [libusb_get_string_descriptor_ascii-iVendor] %s\n", libusb_error_name(actual_size));
			continue;
		}
		vendor_name[actual_size] = '\0';
		actual_size = libusb_get_string_descriptor_ascii(device_handle, device_detail.iProduct, product_name, sizeof(product_name));
		if(actual_size < 0){
			libusb_close(device_handle);
			fprintf(stderr, "[E] [libusb_get_string_descriptor_ascii-iProduct] %s\n", libusb_error_name(actual_size));
			continue;
		}
		product_name[actual_size] = '\0';
		#ifdef APP_DEBUG
		fprintf(stdout,"%s\n",vendor_name);
		fprintf(stdout,"%s\n",product_name);
		fprintf(stdout,"%x\n",device_detail.idVendor);
		fprintf(stdout,"%x\n",device_detail.idProduct );
		fprintf(stdout,"--------------------------\n");
		#endif
		if(strncmp((const char*)vendor_name,FOS_PROTO_VENDOR_STRING,strlen(FOS_PROTO_VENDOR_STRING)) == 0 && strncmp((const char*)product_name,FOS_PROTO_PRODUCT_STRING,strlen(FOS_PROTO_PRODUCT_STRING)) == 0 && device_detail.idVendor == FOS_PROTO_VENDOR_ID && device_detail.idProduct == FOS_PROTO_PRODUCT_ID){
			#ifdef APP_DEBUG
				fprintf(stdout,"DeviceNo: %zd\n",i);
				fprintf(stdout,"\tDeviceMajorMinor: [0x%04x:0x%04x] \n",device_detail.idVendor,device_detail.idProduct);
				fprintf(stdout,"\tDeviceVendorName: %s\n",vendor_name);
				fprintf(stdout,"\tDeviceProductName: %s\n",product_name);
			#endif
			struct libusb_config_descriptor *config;
			errcode = libusb_get_active_config_descriptor(device_list[i], &config);
			if(errcode < 0){
				fprintf(stderr, "[E] [libusb_get_active_config_descriptor] %s\n", libusb_error_name(errcode));
			}else{
				int device_config;
				errcode = libusb_get_configuration(device_handle,&device_config);
				if(errcode == 0){
					//! Set Configuration if not set
					if(device_config != 1){
						errcode = libusb_set_configuration(device_handle, 1);
							if(errcode != 0) break;
					}
					//! Claim Interface
					errcode = libusb_claim_interface(device_handle, 0);
					if(errcode == 0){
						//! Activate Configuration
						is_device_found = 1;
						for(uint8_t j = 0; j < config->bNumInterfaces; ++j) {
							const struct libusb_interface *itf = &config->interface[j];
							for(uint8_t k = 0; k < itf->num_altsetting; ++k) {
								const struct libusb_interface_descriptor *itf_desc = &itf->altsetting[k];
								for(int k = 0; k < itf_desc->bNumEndpoints; k++){
									const struct libusb_endpoint_descriptor *ep_desc = &itf_desc->endpoint[k];
									#ifdef APP_DEBUG
									fprintf(stdout,"\nEndPoint Descriptors: ");
									fprintf(stdout,"\n\tSize of EndPoint Descriptor: %d", ep_desc->bLength);
									fprintf(stdout,"\n\tType of Descriptor: %d", ep_desc->bDescriptorType);
									fprintf(stdout,"\n\tEndpoint Address: 0x0%x", ep_desc->bEndpointAddress);
									fprintf(stdout,"\n\tMaximum Packet Size: %x", ep_desc->wMaxPacketSize);
									fprintf(stdout,"\n\tAttributes applied to Endpoint: %d", ep_desc->bmAttributes);
									fprintf(stdout,"\n\tInterval for Polling for data Transfer: %d\n", ep_desc->bInterval);
									#endif
								}
							}
						}
					}
					errcode = libusb_release_interface(device_handle, 0);
					#ifdef APP_DEBUG
					if (errcode != LIBUSB_SUCCESS) {
					fprintf(stderr, "Failed to release interface: %s\n", libusb_error_name(errcode));
					
					}
					#endif

				}
				libusb_free_config_descriptor(config);
			}
			libusb_close(device_handle);
			break;
		}
		libusb_close(device_handle);
	}
	libusb_free_device_list(device_list,1);
	return is_device_found;
}
int GenID_VerifyUsingSecurityKey(void){
	int is_authenticated = 0;
    bool is_done = false;
	for(int i = 1; i < 5; i++){
		libusb_context* app_contex;
		char device_register_id[100];
		if(libusb_init(&app_contex) == 0 && GenID_Load(GNID_REGISTER_ID_FILEPATH,device_register_id,sizeof(device_register_id))){
			//! SecurityKey Connected?
			SecurityKey_t security_key;
			if(GenID_IsSecurityConnected(app_contex)){
				if(is_done == false){
					GenID_DisplayLANConfigurationMenu();
				}
				if(is_done){
					uint8_t request_id[4];
					GenID_SecurityKey_isConnected_ex(app_contex,&security_key);
					if(GenID_SecurityKey_QueryKey(&security_key,request_id)){
						char _rsecret[255];
						if(GenID_SecurityKey_CheckResp(&security_key,request_id,_rsecret)){
							if(strcasecmp(device_register_id,_rsecret) == 0){
								is_authenticated = 1;
								//! Clean Up
								libusb_exit(app_contex);
								break;
							}
						}
					}
				}
				is_done = true;
			}
			libusb_exit(app_contex);
		}else fprintf(stderr, "[E] [GenID_VerifyUsingSecurityKey] %s\n", strerror(errno));
		sleep(10);
	}
	return is_authenticated;
}
int GenID_ReadUUID_Ex(char* _uuid){
	if(_uuid){
		char tmp[DISK_IDENT_SIZE] = {0};
		int fd = open("/dev/ada0",O_RDONLY);
		if(fd < 0){
            fprintf(stderr, "[E] Failed to Open Disk: %s\n", strerror(errno));
            return 0;
		}
		if (ioctl(fd, DIOCGIDENT,tmp) < 0) {
            fprintf(stderr, "[E] Failed to Read UUID: %s\n", strerror(errno));
            close(fd);
            return 0;
        }
		strcpy(_uuid, tmp);
		close(fd);
		return 1;
	}
	return 0;
}
int GenID_ReadUUID(char* _uuid){
    if(_uuid){
        int _mib[2];
        char _m_uuid[37];
        size_t _uuid_size = sizeof(_m_uuid);
        _mib[0] = CTL_KERN;
        _mib[1] = KERN_HOSTUUID;
        if(sysctl(_mib, 2, _m_uuid, &_uuid_size, NULL, 0) != -1){
            _m_uuid[_uuid_size] = '\0';
            strcpy(_uuid, _m_uuid);
			fprintf(stdout,"[GenID_ReadUUID] %s\n",_uuid);
            return 1;
        }
    }
    return 0;
}
int GenID_CalcCRC64(const uint8_t* _data, const size_t _datalen, uint64_t* _data_crc){
    if(_data && _datalen && _data_crc){
	// CRC-64 polynomial
		const uint64_t polynomial = 0x42F0E1EBA9EA3693;
		uint64_t crc = 0xFFFFFFFFFFFFFFFF; // Initial value
		for (size_t i = 0; i < _datalen; i++) {
			crc ^= _data[i]; // XOR byte into CRC
			for (int j = 0; j < 8; j++) { // Process each bit
				if (crc & 1) { // If the LSB is set
					crc = (crc >> 1) ^ polynomial; // Shift right and XOR with polynomial
				} else {
					crc >>= 1; // Just shift right
				}
			}
		}
		*_data_crc = crc;
		return 1;
	}
    return 0;
}
int GenID_GetAllEthernetAddresses(Layer2Vector_t* _addrs){
    if(_addrs){
        struct ifaddrs* interfaces;
        struct ifaddrs* next_interface;
    	struct ifmediareq ifmr;
    	unsigned char* next_phy_addr;
		int eggs[6];
    	if(getifaddrs(&interfaces) == 0 && GenID_GetScrambledEggs(eggs,6)){
    		next_interface = interfaces;
    		int fd = socket(AF_UNIX,SOCK_DGRAM,0);
    		while(next_interface != NULL && fd > -1){
    			if(next_interface->ifa_addr->sa_family == AF_LINK){
    				//! read physical addr
    				next_phy_addr = (unsigned char*)LLADDR((struct sockaddr_dl*)next_interface->ifa_addr);
    				//! validate address
    				if(!next_phy_addr[0] && !next_phy_addr[1] && !next_phy_addr[2] &&
    				   !next_phy_addr[3] && !next_phy_addr[4] && !next_phy_addr[5]){
    					   next_interface = next_interface->ifa_next;
    					   continue;
    				}
    				//! read media type
    				memset(&ifmr,0, sizeof(ifmr));
    				strcpy(ifmr.ifm_name,next_interface->ifa_name);
    				if(ioctl(fd,SIOCGIFMEDIA,(caddr_t)&ifmr) > -1)
    					if(IFM_TYPE(ifmr.ifm_active) == IFM_ETHER){
                           //! Populate interface data
							uint8_t layer2_addr_tmp[12];
							char* layer2_key;
							char* layer2_value;
							//! Apply Obfuscation
							next_phy_addr[0] = next_phy_addr[2] ^ eggs[0];
							next_phy_addr[1] = next_phy_addr[4] ^ eggs[1];
							next_phy_addr[2] = next_phy_addr[0] ^ eggs[2];
							next_phy_addr[3] = next_phy_addr[5] ^ eggs[3];
							next_phy_addr[4] = next_phy_addr[1] ^ eggs[4];
							next_phy_addr[5] = next_phy_addr[3] ^ eggs[5];
							//! Copy
							memcpy(layer2_addr_tmp,next_phy_addr,6);
							//! Bit Manipulation
							layer2_addr_tmp[6]  = layer2_addr_tmp[0] | layer2_addr_tmp[5];
							layer2_addr_tmp[7]  = layer2_addr_tmp[4] & layer2_addr_tmp[1];
							layer2_addr_tmp[8]  = layer2_addr_tmp[2] ^ layer2_addr_tmp[3];
							layer2_addr_tmp[9]  = layer2_addr_tmp[2] ^ layer2_addr_tmp[3];
							layer2_addr_tmp[10] = layer2_addr_tmp[4] & layer2_addr_tmp[1];
							layer2_addr_tmp[11] = layer2_addr_tmp[0] | layer2_addr_tmp[5];
							//! Generate Key Value
							if(GenID_CalcKey(next_phy_addr,sizeof(next_phy_addr),&layer2_key) && GenID_CalcDigest(layer2_addr_tmp,sizeof(layer2_addr_tmp),layer2_addr_tmp,sizeof(layer2_addr_tmp),&layer2_value)){
								Layer2Vector_insert(_addrs,layer2_key,layer2_value);
								if(layer2_key) free(layer2_key);
								if(layer2_value) free(layer2_value);
							}
                        }
    			}
    			next_interface = next_interface->ifa_next;
    		}
    		freeifaddrs(interfaces);
    		close(fd);
    		return 1;
    	}
    }
	return 0;
}
int GenID_GetJsonOf(const Layer2Vector_t* _addr, char* _json, const size_t _jsonsize){
    if(_addr == NULL || _json == NULL || _jsonsize == 0) return 0;
    int retcode = 0;
	struct json_object *root = json_object_new_object();
	if(root){
		struct json_object *layer2_list = json_object_new_array();
		if(layer2_list){
			for(int i = 0; i < _addr->size; i++){
				struct json_object *node = json_object_new_object();
				json_object_object_add(node,_addr->data[i].key, json_object_new_string(_addr->data[i].value));
				json_object_array_add(layer2_list, node);
			}
			json_object_object_add(root, "AuthLayer", layer2_list);
			const char* json_data = json_object_to_json_string_ext(root,JSON_C_TO_STRING_NOZERO);
			if(json_data){
				snprintf(_json,_jsonsize,"%s",json_data);
				retcode = 1;
			}
		}
		json_object_put(root);
	}
	return retcode;	
}
int GenID_GetScrambledEggs(int* _eggs, const size_t _eggs_max){
	if(_eggs == NULL || _eggs_max == 0) return 0;
	char _local_uuid[DISK_IDENT_SIZE];
	uint64_t _local_uuid_crc = 0;
	if(GenID_ReadUUID_Ex(_local_uuid) && GenID_CalcCRC64((uint8_t*)_local_uuid,strlen(_local_uuid),&_local_uuid_crc)){
        srand(_local_uuid_crc);
		for(int i = 0; i < _eggs_max; i++) _eggs[i] = rand();
		return 1;
	}
	return 0;
}
int GenID_Dump(const char* _filepath, const char* _data){
    if(_filepath && _data){
        FILE* data_writer = fopen(_filepath,"wb");
        if(data_writer){
            fprintf(data_writer,"%s",_data);
            fclose(data_writer);
            return 1;
        }
    }
    return 0;
}
int GenID_Load(const char* _filepath, char* _data, size_t _datalen){
    if(_filepath && _data && _datalen){
        FILE* data_reader = fopen(_filepath,"rb");
        if(data_reader){
            fgets(_data,_datalen,data_reader);
			size_t length_till_newline = strcspn(_data,"\n");
			if(length_till_newline > 0) _data[length_till_newline] = '\0';
            fclose(data_reader);
            if(strlen(_data) > 0) return 1;
        }
    }
    return 0;	
}
int GenID_DoRegister(const char* _layers2json,const char* _access_token){
    int retcode = 0;
    if(_layers2json && _access_token){
        CURL *curl_handle;
        CURLcode curl_err;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_handle = curl_easy_init();
        long HTTPcode = 404;
        char HTTPData[HTTP_MAX_RESPONSE_SIZE];
        char HTTPEndpoint[200];
        snprintf(HTTPEndpoint,200,"https://firewall.thingzeye.com/thingzeye_enterprise/%s/ot_registration",_access_token);
        #ifdef DEBUG_GENID
        fprintf(stdout,"%s\n",HTTPEndpoint);
        #endif
	    if(curl_handle){    
			curl_easy_setopt(curl_handle, CURLOPT_URL, HTTPEndpoint);
			curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, (long) strlen(_layers2json));
			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS,_layers2json);
			struct curl_slist *curl_header_options = NULL;
			curl_header_options = curl_slist_append(curl_header_options, "Content-Type: application/json");
			curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, curl_header_options);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, GenID_WriteCallback);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, HTTPData);
			#ifdef DEBUG_GENID
			curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
			#endif
			curl_err = curl_easy_perform(curl_handle);
			curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &HTTPcode);
			if(curl_err == CURLE_OK && HTTPcode == 200){
				retcode = 1;
                #ifdef DEBUG_GENID
                fprintf(stdout,"Registratioin Status: %s\n",HTTPData);
                #endif
                struct json_object *root = json_tokener_parse(HTTPData);
                struct json_object *key = NULL;
                if(root){
					//! Dump Layers
					GenID_Dump(GNID_VERIFICATION_FILEPATH,_layers2json);
                    //! Registration Key
                    if (json_object_object_get_ex(root, "key", &key)){
                        char _key[100];
                        snprintf(_key,100,"%s",json_object_get_string(key));
                        GenID_Dump(GNID_REGISTER_ID_FILEPATH,_key);
                    }
                    //! Registration Expiry
                    if (json_object_object_get_ex(root, "expired_on", &key)){
                        char _key[100];
                        snprintf(_key,100,"%d",json_object_get_int(key));
                        GenID_Dump(GNID_REGISTER_EXPIRE_FILEPATH,_key);
                    }
                    //! Next Access Token
                    if (json_object_object_get_ex(root, "next_key", &key)){
                        char _key[100];
                        snprintf(_key,100,"%s",json_object_get_string(key));
                        GenID_Dump(GNID_ACCESS_TOKEN_FILEPATH,_key);
                    }
                    json_object_put(root);
                }
			}else{
                fprintf(stdout,"Error While Registring Firewall: %s\n",HTTPData);
            }
		}
		curl_easy_cleanup(curl_handle);
	}
	curl_global_cleanup();
    return retcode;
}

int GenID_DoCheckRegister(const char* _layers2json,const char* _reg_id){
    int retcode = 0;
    if(_layers2json && _reg_id){
        CURL *curl_handle;
        CURLcode curl_err;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_handle = curl_easy_init();
        long HTTPcode = 404;
        char HTTPData[HTTP_MAX_RESPONSE_SIZE];
        char HTTPEndpoint[300];
        snprintf(HTTPEndpoint,sizeof(HTTPEndpoint),"https://firewall.thingzeye.com/thingzeye_enterprise/%s/ot_verification",_reg_id);
        #ifdef DEBUG_GENID
        fprintf(stdout,"%s\n",HTTPEndpoint);
        #endif
	    
	    if(curl_handle){    
			curl_easy_setopt(curl_handle, CURLOPT_URL, HTTPEndpoint);
			curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
			curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS,_layers2json);
			struct curl_slist *curl_header_options = NULL;
			curl_header_options = curl_slist_append(curl_header_options, "Content-Type: application/json");
			curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, curl_header_options);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, GenID_WriteCallback);
			curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, HTTPData);
			#ifdef DEBUG_GENID
			curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
			#endif
			curl_err = curl_easy_perform(curl_handle);
			curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &HTTPcode);
			
			if(curl_err == CURLE_OK && HTTPcode == 200){
				//! Dump again,
				#ifdef DEBUG_GENID
				fprintf(stdout,"%s\n",_layers2json);
				#endif
				if(GenID_Dump(GNID_VERIFICATION_FILEPATH,_layers2json)) retcode = 1;
			}else{
                fprintf(stderr,"Error While Firewall Registration Verification: %s\n",HTTPData);
            }
		}
		curl_easy_cleanup(curl_handle);
	}
	curl_global_cleanup();
    return retcode;
}
int GenID_CalcKey(const uint8_t* _key, const size_t _keylen,char** _keystr){
	if(_key == NULL || _keylen == 0 || _keystr == NULL) return 0;
	uint64_t _keycrc = 0;
	if(GenID_CalcCRC64(_key,_keylen,&_keycrc)){
		*_keystr = (char*)malloc(sizeof(uint64_t) * 2 + 1);
		if(*_keystr){
			char* ptr = *_keystr;
			sprintf(ptr,"%0lx",_keycrc);
			return 1;
		}
	}
	return 0;
}	

int GenID_CalcDigest(uint8_t* _key,size_t _keylen,uint8_t* _item,size_t _itemlen, char** _mac){
	if(_key == NULL || _keylen == 0||_item == NULL || _itemlen == 0 || _mac == NULL) return 0;
	uint8_t _item_mac[EVP_MAX_MD_SIZE];
    unsigned int _item_maclen = 0;
	HMAC(EVP_sha256(), _key, _keylen, _item, _itemlen, _item_mac, &_item_maclen);
	*_mac = (char*)malloc(_item_maclen * 2 + 1);
	if(*_mac){
		char* ptr = *_mac;
		for(int i = 0 ; i < _item_maclen; i++){
			snprintf(ptr,3,"%02x",_item_mac[i]);
			ptr += 2;
		}
		return 1;
	}
	return 0;
}
int GenID_GetAllEthernetAddressesFromFile(Layer2Vector_t* _addrs){
    if(_addrs == NULL) return 0;
    // Parse JSON string
	int statuscode = 0;
    struct json_object *__root = json_object_from_file(GNID_VERIFICATION_FILEPATH);
    struct json_object* l2_list;
    int count = 0;
    if(__root){
		if(json_object_object_get_ex(__root, "AuthLayer",&l2_list)){
			if(json_object_get_type(l2_list) == json_type_array){
				int l2_size = json_object_array_length(l2_list);
				for(int i = 0; i < l2_size && i < MAX_INTERFACES; i++){
					struct json_object *element = json_object_array_get_idx(l2_list,i);
					if(element != NULL){
						if(json_object_get_type(element) == json_type_object){
							struct json_object_iterator h = json_object_iter_begin(element);
							struct json_object_iterator t = json_object_iter_end(element);
							if(!json_object_iter_equal(&h,&t)){
								if(!Layer2Vector_insert(_addrs,json_object_iter_peek_name(&h),json_object_get_string(json_object_iter_peek_value(&h)))){
									break;
								} 
							}
						}
					}
				}
				statuscode = 1;
			}
		}
        json_object_put(__root);
    }

    return statuscode;
}
int GenID_VerifyOffline(const Layer2Vector_t* _genaddrs){
	if(_genaddrs == NULL || _genaddrs->size < 2) return 0;
	Layer2Vector_t _fileaddrs;
	Layer2Vector_Init(&_fileaddrs);
	if(GenID_GetAllEthernetAddressesFromFile(&_fileaddrs) && _fileaddrs.size >= 2){
		#ifdef DEBUG_GENID
		fprintf(stdout,"GenID_VerifyOffline:\n");
		Layer2Vector_PrintAll(&_fileaddrs);
		#endif
		size_t l2_match_count = 0;
		for(int i = 0; i < _genaddrs->size; i++){
			for(int j = 0; j < _fileaddrs.size; j++)
				if(strcmp(_fileaddrs.data[j].key,_genaddrs->data[i].key) == 0 && strcmp(_fileaddrs.data[j].value,_genaddrs->data[i].value) == 0)
					l2_match_count++;
		}
		Layer2Vector_DeInit(&_fileaddrs);
		return l2_match_count >= SUCCESS_COUNT? 1 : 0;	
	}
	Layer2Vector_DeInit(&_fileaddrs);
	return 0;
}
