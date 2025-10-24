/**
 @file  protocol.h
 @brief ENet protocol
*/
#ifndef __ENET_PROTOCOL_H__
#define __ENET_PROTOCOL_H__

#include "enet/types.h"

enum
{
   ENET_PROTOCOL_MINIMUM_MTU             = 576,
   ENET_PROTOCOL_MAXIMUM_MTU             = 4096,
   ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS = 32,
   ENET_PROTOCOL_MINIMUM_WINDOW_SIZE     = 4096,
   ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE     = 65536,
   ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT   = 1,
   ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT   = 255,
   ENET_PROTOCOL_MAXIMUM_PEER_ID         = 0xFFF,
   ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT  = 1024 * 1024
};

typedef enum _ENetProtocolCommand
{
   ENET_PROTOCOL_COMMAND_NONE               = 0,
   ENET_PROTOCOL_COMMAND_ACKNOWLEDGE        = 1,
   ENET_PROTOCOL_COMMAND_CONNECT            = 2,
   ENET_PROTOCOL_COMMAND_VERIFY_CONNECT     = 3,
   ENET_PROTOCOL_COMMAND_DISCONNECT         = 4,
   ENET_PROTOCOL_COMMAND_PING               = 5,
   ENET_PROTOCOL_COMMAND_SEND_RELIABLE      = 6,
   ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE    = 7,
   ENET_PROTOCOL_COMMAND_SEND_FRAGMENT      = 8,
   ENET_PROTOCOL_COMMAND_SEND_UNSEQUENCED   = 9,
   ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT    = 10,
   ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE = 11,
   ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT = 12,
   ENET_PROTOCOL_COMMAND_COUNT              = 13,

   ENET_PROTOCOL_COMMAND_MASK               = 0x0F
} ENetProtocolCommand;

typedef enum _ENetProtocolFlag
{
   ENET_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE = (1 << 7),
   ENET_PROTOCOL_COMMAND_FLAG_UNSEQUENCED = (1 << 6),

   ENET_PROTOCOL_HEADER_FLAG_COMPRESSED = (1 << 14),
   ENET_PROTOCOL_HEADER_FLAG_SENT_TIME  = (1 << 15),
   ENET_PROTOCOL_HEADER_FLAG_MASK       = ENET_PROTOCOL_HEADER_FLAG_COMPRESSED | ENET_PROTOCOL_HEADER_FLAG_SENT_TIME,

   ENET_PROTOCOL_HEADER_SESSION_MASK    = (3 << 12),
   ENET_PROTOCOL_HEADER_SESSION_SHIFT   = 12
} ENetProtocolFlag;

typedef enum _ENetSocks5State
{
   ENET_SOCKS5_STATE_NONE,
   ENET_SOCKS5_STATE_SEND_AUTH_REQUEST,
   ENET_SOCKS5_STATE_RECEIVE_AUTH_RESPONSE,
   ENET_SOCKS5_STATE_SEND_AUTH_REQUEST_USERNAME,
   ENET_SOCKS5_STATE_RECEIVE_AUTH_RESPONSE_USERNAME,
   ENET_SOCKS5_STATE_SEND_REQUEST,
   ENET_SOCKS5_STATE_RECEIVE_RESPONSE,
   ENET_SOCKS5_STATE_CONNECTION_FAILED,
   ENET_SOCKS5_STATE_CONNECTED
} ENetSocks5State;

typedef enum _ENetSocks5Version
{
   ENET_SOCKS5_VERSION_UNDEFINED = 0x00,
   ENET_SOCKS5_VERSION_5         = 0x05
} ENetSocks5Version;

typedef enum _ENetSocks5AuthMethod
{
   ENET_SOCKS5_AUTH_NO_AUTH              = 0x00,
   ENET_SOCKS5_AUTH_GSSAPI               = 0x01,
   ENET_SOCKS5_AUTH_USERNAME_PASSWORD    = 0x02,
   ENET_SOCKS5_AUTH_UNDEFINED            = 0xFE,
   ENET_SOCKS5_AUTH_NO_ACCEPTABLE        = 0xFF
} ENetSocks5AuthMethod;

typedef enum _ENetSocks5Command
{
   ENET_SOCKS5_COMMAND_UNDEFINED      = 0x00,
   ENET_SOCKS5_COMMAND_CONNECT        = 0x01,
   ENET_SOCKS5_COMMAND_BIND           = 0x02,
   ENET_SOCKS5_COMMAND_UDP_ASSOCIATE  = 0x03
} ENetSocks5Command;

typedef enum _ENetSocks5AddressType
{
   ENET_SOCKS5_ADDRESS_UNDEFINED   = 0x00,
   ENET_SOCKS5_ADDRESS_IPV4        = 0x01,
   ENET_SOCKS5_ADDRESS_DOMAIN_NAME = 0x03,
   ENET_SOCKS5_ADDRESS_IPV6        = 0x04
} ENetSocks5AddressType;

typedef enum _ENetSocks5ReplyType
{
   ENET_SOCKS5_REPLY_SUCCEEDED               = 0x00,
   ENET_SOCKS5_REPLY_GENERAL_FAILURE         = 0x01,
   ENET_SOCKS5_REPLY_NOT_ALLOWED             = 0x02,
   ENET_SOCKS5_REPLY_NETWORK_UNREACHABLE     = 0x03,
   ENET_SOCKS5_REPLY_HOST_UNREACHABLE        = 0x04,
   ENET_SOCKS5_REPLY_CONNECTION_REFUSED      = 0x05,
   ENET_SOCKS5_REPLY_TTL_EXPIRED             = 0x06,
   ENET_SOCKS5_REPLY_COMMAND_NOT_SUPPORTED   = 0x07,
   ENET_SOCKS5_REPLY_ADDRESS_TYPE_UNSUPPORTED = 0x08
} ENetSocks5ReplyType;

typedef struct _ENetSocks5Authentication
{
   char* username;
   char* password;
} ENetSocks5Authentication;

typedef struct _ENetSocks5Info
{
   char* ip;
   enet_uint16 port;
   ENetSocks5Authentication auth;
} ENetSocks5Info;

#ifdef _MSC_VER
#pragma pack(push, 1)
#define ENET_PACKED
#elif defined(__GNUC__) || defined(__clang__)
#define ENET_PACKED __attribute__ ((packed))
#else
#define ENET_PACKED
#endif

typedef struct _ENetSocks5Ipv4
{
   union {
      enet_uint32 addr;
      enet_uint8 parts[4];
      struct {
         enet_uint8 part4;
         enet_uint8 part3;
         enet_uint8 part2;
         enet_uint8 part1;
      };
   };
   enet_uint16 port;
} ENET_PACKED ENetSocks5Ipv4;

typedef struct _ENetSocks5Ipv6
{
   union {
      enet_uint16 parts[8];
      struct {
         enet_uint16 part8;
         enet_uint16 part7;
         enet_uint16 part6;
         enet_uint16 part5;
         enet_uint16 part4;
         enet_uint16 part3;
         enet_uint16 part2;
         enet_uint16 part1;
      };
   };
   enet_uint16 port;
} ENET_PACKED ENetSocks5Ipv6;

typedef struct _ENetSocks5DomainName
{
   enet_uint8 length;
   enet_uint8 name[255];
   enet_uint16 port;
} ENET_PACKED ENetSocks5DomainName;

typedef struct _ENetSocks5AuthRequest
{
   enet_uint8 version;
   enet_uint8 authMethodCount;
   enet_uint8 authMethods[255];
} ENET_PACKED ENetSocks5AuthRequest;

typedef struct _ENetSocks5AuthRequestUsername
{
   enet_uint8 version;
   enet_uint8 usernameLength;
   enet_uint8 username[255];
   enet_uint8 passwordLength;
   enet_uint8 password[255];
} ENET_PACKED ENetSocks5AuthRequestUsername;

typedef struct _ENetSocks5AuthResponse
{
   enet_uint8 version;
   enet_uint8 authMethod;
} ENET_PACKED ENetSocks5AuthResponse;

typedef struct _ENetSocks5Request
{
   enet_uint8 version;
   enet_uint8 command;
   enet_uint8 reserved;
   enet_uint8 addressType;
   ENetSocks5Ipv4 ipv4;
} ENET_PACKED ENetSocks5Request;

typedef struct _ENetSocks5Response
{
   enet_uint8 version;
   enet_uint8 replyType;
   enet_uint8 reserved;
   enet_uint8 addressType;
   ENetSocks5Ipv4 ipv4;
} ENET_PACKED ENetSocks5Response;

typedef struct _ENetSocks5Header
{
   enet_uint16 reserved;
   enet_uint8 fragment;
   enet_uint8 addressType;
   ENetSocks5Ipv4 ipv4;
} ENET_PACKED ENetSocks5Header;

typedef struct _ENetProtocolHeader
{
   enet_uint16 peerID;
   enet_uint16 sentTime;
} ENET_PACKED ENetProtocolHeader;

typedef struct _ENetNewProtocolHeader
{
    enet_uint16 integrity[3];
    enet_uint16 peerID;
    enet_uint16 sentTime;
} ENET_PACKED ENetNewProtocolHeader;

typedef struct _ENetProtocolCommandHeader
{
   enet_uint8 command;
   enet_uint8 channelID;
   enet_uint16 reliableSequenceNumber;
} ENET_PACKED ENetProtocolCommandHeader;

typedef struct _ENetProtocolAcknowledge
{
   ENetProtocolCommandHeader header;
   enet_uint16 receivedReliableSequenceNumber;
   enet_uint16 receivedSentTime;
} ENET_PACKED ENetProtocolAcknowledge;

typedef struct _ENetProtocolConnect
{
   ENetProtocolCommandHeader header;
   enet_uint16 outgoingPeerID;
   enet_uint8  incomingSessionID;
   enet_uint8  outgoingSessionID;
   enet_uint32 mtu;
   enet_uint32 windowSize;
   enet_uint32 channelCount;
   enet_uint32 incomingBandwidth;
   enet_uint32 outgoingBandwidth;
   enet_uint32 packetThrottleInterval;
   enet_uint32 packetThrottleAcceleration;
   enet_uint32 packetThrottleDeceleration;
   enet_uint32 connectID;
   enet_uint32 data;
} ENET_PACKED ENetProtocolConnect;

typedef struct _ENetProtocolVerifyConnect
{
   ENetProtocolCommandHeader header;
   enet_uint16 outgoingPeerID;
   enet_uint8  incomingSessionID;
   enet_uint8  outgoingSessionID;
   enet_uint32 mtu;
   enet_uint32 windowSize;
   enet_uint32 channelCount;
   enet_uint32 incomingBandwidth;
   enet_uint32 outgoingBandwidth;
   enet_uint32 packetThrottleInterval;
   enet_uint32 packetThrottleAcceleration;
   enet_uint32 packetThrottleDeceleration;
   enet_uint32 connectID;
} ENET_PACKED ENetProtocolVerifyConnect;

typedef struct _ENetProtocolBandwidthLimit
{
   ENetProtocolCommandHeader header;
   enet_uint32 incomingBandwidth;
   enet_uint32 outgoingBandwidth;
} ENET_PACKED ENetProtocolBandwidthLimit;

typedef struct _ENetProtocolThrottleConfigure
{
   ENetProtocolCommandHeader header;
   enet_uint32 packetThrottleInterval;
   enet_uint32 packetThrottleAcceleration;
   enet_uint32 packetThrottleDeceleration;
} ENET_PACKED ENetProtocolThrottleConfigure;

typedef struct _ENetProtocolDisconnect
{
   ENetProtocolCommandHeader header;
   enet_uint32 data;
} ENET_PACKED ENetProtocolDisconnect;

typedef struct _ENetProtocolPing
{
   ENetProtocolCommandHeader header;
} ENET_PACKED ENetProtocolPing;

typedef struct _ENetProtocolSendReliable
{
   ENetProtocolCommandHeader header;
   enet_uint16 dataLength;
} ENET_PACKED ENetProtocolSendReliable;

typedef struct _ENetProtocolSendUnreliable
{
   ENetProtocolCommandHeader header;
   enet_uint16 unreliableSequenceNumber;
   enet_uint16 dataLength;
} ENET_PACKED ENetProtocolSendUnreliable;

typedef struct _ENetProtocolSendUnsequenced
{
   ENetProtocolCommandHeader header;
   enet_uint16 unsequencedGroup;
   enet_uint16 dataLength;
} ENET_PACKED ENetProtocolSendUnsequenced;

typedef struct _ENetProtocolSendFragment
{
   ENetProtocolCommandHeader header;
   enet_uint16 startSequenceNumber;
   enet_uint16 dataLength;
   enet_uint32 fragmentCount;
   enet_uint32 fragmentNumber;
   enet_uint32 totalLength;
   enet_uint32 fragmentOffset;
} ENET_PACKED ENetProtocolSendFragment;

typedef union _ENetProtocol
{
   ENetProtocolCommandHeader header;
   ENetProtocolAcknowledge acknowledge;
   ENetProtocolConnect connect;
   ENetProtocolVerifyConnect verifyConnect;
   ENetProtocolDisconnect disconnect;
   ENetProtocolPing ping;
   ENetProtocolSendReliable sendReliable;
   ENetProtocolSendUnreliable sendUnreliable;
   ENetProtocolSendUnsequenced sendUnsequenced;
   ENetProtocolSendFragment sendFragment;
   ENetProtocolBandwidthLimit bandwidthLimit;
   ENetProtocolThrottleConfigure throttleConfigure;
} ENET_PACKED ENetProtocol;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

#endif /* __ENET_PROTOCOL_H__ */
