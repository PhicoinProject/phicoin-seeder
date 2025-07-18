// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Copyright (C) 2020 The Raven Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <vector>
#include <stdexcept>

#include "protocol.h"
#include "util.h"
#include "netbase.h"


#ifndef WIN32

# include <arpa/inet.h>

#endif

static const char *ppszTypeName[] =
        {
                "ERROR",
                "tx",
                "block",
        };
//  pchMessageStart[0] = 0x50; // 'P'
//         pchMessageStart[1] = 0x48; // 'H'
//         pchMessageStart[2] = 0x49; // 'I'
//         pchMessageStart[3] = 0x58; // 'X'

unsigned char pchMessageStart[4] = {0x50, 0x48, 0x49, 0x58}; // HEX 4 PHI



CMessageHeader::CMessageHeader()
{
    memcpy(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart));
    memset(pchCommand, 0, sizeof(pchCommand));
    pchCommand[1] = 1;
    nMessageSize = -1;
    nChecksum = 0;
}

CMessageHeader::CMessageHeader(const char *pszCommand, unsigned int nMessageSizeIn)
{
    memcpy(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart));
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    nChecksum = 0;
}

std::string CMessageHeader::GetCommand() const
{
    if (pchCommand[COMMAND_SIZE - 1] == 0)
        return std::string(pchCommand, pchCommand + strlen(pchCommand));
    else
        return std::string(pchCommand, pchCommand + COMMAND_SIZE);
}

bool CMessageHeader::IsValid() const
{
    // Check start string
    if (memcmp(pchMessageStart, ::pchMessageStart, sizeof(pchMessageStart)) != 0)
        return false;

    // Check the command string for errors
    for (const char *p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
    {
        if (*p1 == 0)
        {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
                if (*p1 != 0)
                    return false;
        } else if (*p1 < ' ' || *p1 > 0x7E)
            return false;
    }

    // Message size
    if (nMessageSize > MAX_SIZE)
    {
        printf("CMessageHeader::IsValid() : (%s, %u bytes) nMessageSize > MAX_SIZE\n", GetCommand().c_str(), nMessageSize);
        return false;
    }

    return true;
}


CAddress::CAddress() : CService()
{
    Init();
}

CAddress::CAddress(CService ipIn, uint64 nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NETWORK;
    nTime = 100000000;
}

void CAddress::print() const
{
    printf("CAddress(%s)\n", ToString().c_str());
}

CInv::CInv()
{
    type = 0;
    hash = 0;
}

CInv::CInv(int typeIn, const uint256 &hashIn)
{
    type = typeIn;
    hash = hashIn;
}

CInv::CInv(const std::string &strType, const uint256 &hashIn)
{
    int i;
    for (i = 1; i < ARRAYLEN(ppszTypeName); i++)
    {
        if (strType == ppszTypeName[i])
        {
            type = i;
            break;
        }
    }
    if (i == ARRAYLEN(ppszTypeName))
        throw std::out_of_range("CInv::CInv(string, uint256) : unknown type");
    hash = hashIn;
}

bool operator<(const CInv &a, const CInv &b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

bool CInv::IsKnownType() const
{
    return (type >= 1 && type < ARRAYLEN(ppszTypeName));
}

const char *CInv::GetCommand() const
{
    if (!IsKnownType())
        throw std::out_of_range("CInv::GetCommand() : unknown type");
    return ppszTypeName[type];
}

std::string CInv::ToString() const
{
    return "CInv()";
}

void CInv::print() const
{
    printf("CInv\n");
}
