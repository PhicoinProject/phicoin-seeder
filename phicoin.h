#ifndef __INCLUDED_PHICOIN_H__
#define __INCLUDED_PHICOIN_H__

#include <string>
#include <vector>
#include "netbase.h"
#include "protocol.h"

bool TestNode(const CService &cip, int &ban, int &clientV, std::string &clientSV, int &blocks, std::vector<CAddress> *vAddr);

#endif 